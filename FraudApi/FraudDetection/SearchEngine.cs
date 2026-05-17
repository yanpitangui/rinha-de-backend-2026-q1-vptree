using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using FraudApi.Shared;

namespace FraudApi.FraudDetection;

public unsafe class SearchEngine
{
    private readonly Block* _blocks;
    private readonly byte* _labels;
    private readonly int _k;
    private readonly int _nprobe;
    private readonly int _nprobeRetry;
    private readonly int _nprobeExhaust;
    private readonly float[] _centroids;
    private readonly int[] _clusterBlockStart;
    private readonly int[] _clusterBlockLen;
    private readonly short* _bboxMin;
    private readonly short* _bboxMax;
    private readonly int[] _dimOrder;

    // Reciprocal of quantization scale — used in block scanning to convert int16→float
    private const float InvScale = 1.0f / Vectorizer.Scale;

    public SearchEngine(
        Block* blocks, byte* labels,
        float[] centroids, int[] clusterBlockStart, int[] clusterBlockLen,
        short* bboxMin, short* bboxMax,
        int k, int nprobe, int nprobeRetry, int nprobeExhaust,
        int[] dimOrder)
    {
        _blocks = blocks;
        _labels = labels;
        _centroids = centroids;
        _clusterBlockStart = clusterBlockStart;
        _clusterBlockLen = clusterBlockLen;
        _bboxMin = bboxMin;
        _bboxMax = bboxMax;
        _k = k;
        _nprobe = nprobe;
        _nprobeRetry = nprobeRetry;
        _nprobeExhaust = nprobeExhaust;
        _dimOrder = dimOrder;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query)
    {
        // queryF in int16-scale (raw values as float) — matches centroid space
        Span<float> queryF = stackalloc float[16];
        for (int d = 0; d < 14; d++) queryF[d] = query[d];

        Span<int> probeIdx = stackalloc int[_nprobe];
        Span<float> probeDists = stackalloc float[_nprobe];
        probeDists.Fill(float.MaxValue);
        FindNearestClusters(queryF, probeIdx, probeDists, ReadOnlySpan<ulong>.Empty);

        Span<float> best = stackalloc float[5];
        Span<byte> bestLabels = stackalloc byte[5];
        best.Fill(float.MaxValue);
        float bound = float.MaxValue;

        // Reorder query dims by variance (high→low) for early-exit effectiveness
        Span<short> queryOrd = stackalloc short[16];
        for (int di = 0; di < 14; di++) queryOrd[di] = query[_dimOrder[di]];

        ScanProbes(queryOrd, probeIdx, ref bound, best, bestLabels);

        if (_nprobeRetry > 0)
        {
            int fc = 0;
            for (int i = 0; i < 5; i++) fc += bestLabels[i];

            if (fc >= 1 && fc <= 4)
            {
                int words = (_k + 63) >> 6;
                Span<ulong> visited = stackalloc ulong[words];
                visited.Clear();
                for (int i = 0; i < _nprobe; i++)
                    visited[probeIdx[i] >> 6] |= 1UL << (probeIdx[i] & 63);

                // fc∈{2,3} straddles the approval boundary — exhaust more clusters
                int extraProbes = (fc == 2 || fc == 3) ? _nprobeExhaust : _nprobeRetry;
                Span<int> retryIdx = stackalloc int[extraProbes];
                Span<float> retryDists = stackalloc float[extraProbes];
                retryDists.Fill(float.MaxValue);
                FindNearestClusters(queryF, retryIdx, retryDists, visited);
                ScanProbes(queryOrd, retryIdx, ref bound, best, bestLabels);
            }
        }

        int count = 0;
        for (int i = 0; i < 5; i++) count += bestLabels[i];
        return count;
    }

    [SkipLocalsInit]
    private void ScanProbes(Span<short> queryOrd, Span<int> probeIdx,
        ref float bound, Span<float> best, Span<byte> bestLabels)
    {
        float* qf = stackalloc float[16];
        for (int di = 0; di < 14; di++) qf[di] = queryOrd[di] * InvScale;

        float* dptr = stackalloc float[8];

        // Precompute bound in int16-squared space to avoid per-cluster float→long conversion
        long boundInt = bound < float.MaxValue
            ? (long)(bound * ((double)Vectorizer.Scale * Vectorizer.Scale))
            : long.MaxValue;

        int n = probeIdx.Length;
        for (int pi = 0; pi < n; pi++)
        {
            int ci = probeIdx[pi];
            if (boundInt < long.MaxValue && BboxExceedsOrEquals(queryOrd, ci, boundInt)) continue;

            int bStart = _clusterBlockStart[ci];
            int bEnd   = bStart + _clusterBlockLen[ci];
            for (int b = bStart; b < bEnd; b++)
            {
                if (Sse.IsSupported && b + 8 < bEnd)
                    Sse.Prefetch0(_blocks + b + 8);

                if (!ProcessAllDims(_blocks + b, qf, dptr, bound)) continue;
                float prevBound = bound;
                UpdateTopK(dptr, best, bestLabels, b * 8, ref bound);
                if (bound != prevBound)
                    boundInt = (long)(bound * ((double)Vectorizer.Scale * Vectorizer.Scale));
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool BboxExceedsOrEquals(Span<short> query, int ci, long boundInt)
    {
        long lb = 0;
        int bboxBase = ci * 14;
        for (int d = 0; d < 14; d++)
        {
            int q = query[d];
            int lo = _bboxMin[bboxBase + d];
            int hi = _bboxMax[bboxBase + d];
            if (q < lo) { long diff = lo - q; lb += diff * diff; }
            else if (q > hi) { long diff = q - hi; lb += diff * diff; }
            if (lb > boundInt) return true;
        }
        return false;
    }

    // Column-major centroid layout: _centroids[dim * _k + ci]
    // Allows FMA scan of 8 centroids per AVX load (sequential memory, no horizontal sum).
    [SkipLocalsInit]
    private void FindNearestClusters(Span<float> queryF, Span<int> probeIdx, Span<float> probeDists, ReadOnlySpan<ulong> excluded)
    {
        int n = probeIdx.Length;
        float* acc = stackalloc float[_k];

        fixed (float* cPtr = _centroids)
        {
            if (Avx.IsSupported)
            {
                // Initialize acc with (query[0] - centroid[0][ci])^2 for all ci
                float* base0 = cPtr;
                var qv0 = Vector256.Create(queryF[0]);
                for (int ci = 0; ci < _k; ci += 8)
                {
                    var dif = Avx.Subtract(qv0, Avx.LoadVector256(base0 + ci));
                    Avx.Store(acc + ci, Avx.Multiply(dif, dif));
                }

                // FMA-accumulate dims 1–13
                for (int d = 1; d < 14; d++)
                {
                    float* baseD = cPtr + d * _k;
                    var qvd = Vector256.Create(queryF[d]);
                    for (int ci = 0; ci < _k; ci += 8)
                    {
                        var dif = Avx.Subtract(qvd, Avx.LoadVector256(baseD + ci));
                        var cur = Avx.LoadVector256(acc + ci);
                        Avx.Store(acc + ci,
                            Fma.IsSupported
                                ? Fma.MultiplyAdd(dif, dif, cur)
                                : Avx.Add(cur, Avx.Multiply(dif, dif)));
                    }
                }
            }
            else
            {
                // Scalar fallback
                for (int ci = 0; ci < _k; ci++) acc[ci] = 0f;
                for (int d = 0; d < 14; d++)
                {
                    float* baseD = cPtr + d * _k;
                    float qd = queryF[d];
                    for (int ci = 0; ci < _k; ci++) { float dif = qd - baseD[ci]; acc[ci] += dif * dif; }
                }
            }

            // Pick top-n (skip excluded clusters from prior probes)
            bool hasExcluded = excluded.Length > 0;
            for (int ci = 0; ci < _k; ci++)
            {
                if (hasExcluded && (excluded[ci >> 6] & (1UL << (ci & 63))) != 0) continue;
                float dist = acc[ci];
                if (dist < probeDists[n - 1])
                    InsertSorted(probeIdx, probeDists, ci, dist, n);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InsertSorted(Span<int> idx, Span<float> dists, int ci, float dist, int n)
    {
        int pos = n - 1;
        while (pos > 0 && dists[pos - 1] > dist)
        {
            dists[pos] = dists[pos - 1];
            idx[pos] = idx[pos - 1];
            pos--;
        }
        dists[pos] = dist;
        idx[pos] = ci;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe void UpdateTopK(float* dptr, Span<float> best, Span<byte> bestLabels, int labelBase, ref float bound)
    {
        for (int i = 0; i < 8; i++)
        {
            float d = dptr[i];
            if (d >= bound) continue;

            int pos = 3;
            while (pos >= 0 && best[pos] > d)
            {
                best[pos + 1] = best[pos];
                bestLabels[pos + 1] = bestLabels[pos];
                pos--;
            }
            best[pos + 1] = d;
            bestLabels[pos + 1] = _labels[labelBase + i];
            bound = best[4];
        }
    }

    // Returns false when partial-distance early exit fires (all 8 lanes exceed bound).
    // qf is variance-ordered, normalized to [0,1]. Uses FMA where available.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [SkipLocalsInit]
    private static unsafe bool ProcessAllDims(Block* block, float* qf, float* dptr, float bound)
    {
        short* blockBase = (short*)block;

        if (Avx2.IsSupported)
        {
            var scale = Vector256.Create(InvScale);
            var acc = Vector256<float>.Zero;

            for (int di = 0; di < 14; di++)
            {
                var qv  = Vector256.Create(qf[di]);
                var v8  = Vector128.Load(blockBase + di * 8);
                var vf  = Avx.Multiply(Avx.ConvertToVector256Single(Avx2.ConvertToVector256Int32(v8)), scale);
                var dif = Avx.Subtract(vf, qv);

                acc = Fma.IsSupported
                    ? Fma.MultiplyAdd(dif, dif, acc)
                    : Avx.Add(acc, Avx.Multiply(dif, dif));

                // Two partial-distance checkpoints; highest-variance dims first → acc grows fast
                if ((di == 3 || di == 7) && bound < float.MaxValue)
                {
                    if (Avx.MoveMask(Avx.CompareLessThan(acc, Vector256.Create(bound))) == 0)
                        return false;
                }
            }

            Avx.Store(dptr, acc);
            return true;
        }

        if (AdvSimd.IsSupported)
        {
            var scale128 = Vector128.Create(InvScale);
            var acc0 = Vector128<float>.Zero;
            var acc1 = Vector128<float>.Zero;

            for (int di = 0; di < 14; di++)
            {
                var qv   = Vector128.Create(qf[di]);
                var v8   = AdvSimd.LoadVector128(blockBase + di * 8);
                var lo32 = AdvSimd.SignExtendWideningLower(v8.GetLower());
                var hi32 = AdvSimd.SignExtendWideningUpper(v8);
                var lof  = AdvSimd.Multiply(AdvSimd.ConvertToSingle(lo32), scale128);
                var hif  = AdvSimd.Multiply(AdvSimd.ConvertToSingle(hi32), scale128);
                var dlo  = AdvSimd.Subtract(lof, qv);
                var dhi  = AdvSimd.Subtract(hif, qv);
                acc0 = AdvSimd.FusedMultiplyAdd(acc0, dlo, dlo);
                acc1 = AdvSimd.FusedMultiplyAdd(acc1, dhi, dhi);
            }

            AdvSimd.Store(dptr,     acc0);
            AdvSimd.Store(dptr + 4, acc1);
            return true;
        }

        // Scalar fallback
        for (int i = 0; i < 8; i++) dptr[i] = 0f;
        for (int di = 0; di < 14; di++)
        {
            float qd = qf[di];
            short* dd = blockBase + di * 8;
            for (int i = 0; i < 8; i++)
            {
                float d = dd[i] * InvScale - qd;
                dptr[i] += d * d;
            }
        }
        return true;
    }
}
