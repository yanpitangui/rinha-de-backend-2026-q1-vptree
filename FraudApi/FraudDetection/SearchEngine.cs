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
    private readonly int[] _dimOrder; // variance-sorted dim indices, high→low

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

    public int Search(Span<short> query)
    {
        Span<float> queryF = stackalloc float[16];
        for (int d = 0; d < 14; d++) queryF[d] = query[d];

        Span<int> probeIdx = stackalloc int[_nprobe];
        Span<float> probeDists = stackalloc float[_nprobe];
        probeDists.Fill(float.MaxValue);
        FindNearestClusters(queryF, probeIdx, probeDists, ReadOnlySpan<ulong>.Empty);

        Span<int> best = stackalloc int[5];
        Span<byte> bestLabels = stackalloc byte[5];
        best.Fill(int.MaxValue);
        int bound = int.MaxValue;

        fixed (short* qPtr = query)
        fixed (int* dimOrderPtr = _dimOrder)
        {
            ScanProbes(qPtr, query, probeIdx, ref bound, best, bestLabels, dimOrderPtr);

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

                    // fc∈{2,3} straddles approval boundary — use exhaust budget
                    int extraProbes = (fc == 2 || fc == 3) ? _nprobeExhaust : _nprobeRetry;
                    Span<int> retryIdx = stackalloc int[extraProbes];
                    Span<float> retryDists = stackalloc float[extraProbes];
                    retryDists.Fill(float.MaxValue);
                    FindNearestClusters(queryF, retryIdx, retryDists, visited);
                    ScanProbes(qPtr, query, retryIdx, ref bound, best, bestLabels, dimOrderPtr);
                }
            }
        }

        int count = 0;
        for (int i = 0; i < 5; i++) count += bestLabels[i];
        return count;
    }

    private void ScanProbes(short* qPtr, Span<short> query, Span<int> probeIdx,
        ref int bound, Span<int> best, Span<byte> bestLabels, int* dimOrderPtr)
    {
        int n = probeIdx.Length;
        // Align to 32 bytes so AVX2 store/load never fault on aligned variants.
        int* dptrRaw = stackalloc int[16];
        int* dptr = (int*)(((nint)dptrRaw + 31) & ~31);
        for (int pi = 0; pi < n; pi++)
        {
            int ci = probeIdx[pi];
            if (bound < int.MaxValue && BboxExceedsOrEquals(query, ci, bound)) continue;

            int bStart = _clusterBlockStart[ci];
            int bEnd   = bStart + _clusterBlockLen[ci];
            for (int b = bStart; b < bEnd; b++)
            {
                if (Sse.IsSupported && b + 8 < bEnd)
                    Sse.Prefetch0(_blocks + b + 8);

                if (!ProcessAllDims(_blocks + b, qPtr, dptr, dimOrderPtr, bound)) continue;
                bound = UpdateTopK(dptr, best, bestLabels, b * 8, bound);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool BboxExceedsOrEquals(Span<short> query, int ci, int bound)
    {
        int lb = 0;
        int bboxBase = ci * 14;
        for (int d = 0; d < 14; d++)
        {
            int q = query[d];
            int lo = _bboxMin[bboxBase + d];
            int hi = _bboxMax[bboxBase + d];
            if (q < lo) { int diff = lo - q; lb += diff * diff; }
            else if (q > hi) { int diff = q - hi; lb += diff * diff; }
            if (lb > bound) return true;
        }
        return false;
    }

    private void FindNearestClusters(Span<float> queryF, Span<int> probeIdx, Span<float> probeDists, ReadOnlySpan<ulong> excluded)
    {
        int n = probeIdx.Length;
        bool hasExcluded = excluded.Length > 0;

        fixed (float* cPtr = _centroids)
        fixed (float* qfPtr = queryF)
        {
#if TARGET_X64
            if (Avx.IsSupported && Sse.IsSupported)
            {
                var qv0 = Avx.LoadVector256(qfPtr);
                var qv1 = Avx.LoadVector256(qfPtr + 8);

                for (int ci = 0; ci < _k; ci++)
                {
                    if (hasExcluded && (excluded[ci >> 6] & (1UL << (ci & 63))) != 0) continue;

                    float* c = cPtr + ci * 16;
                    var d0 = Avx.Subtract(qv0, Avx.LoadVector256(c));
                    var d1 = Avx.Subtract(qv1, Avx.LoadVector256(c + 8));
                    d0 = Avx.Multiply(d0, d0);
                    d1 = Avx.Multiply(d1, d1);
                    var sum = Avx.Add(d0, d1);
                    var lo128 = sum.GetLower();
                    var hi128 = sum.GetUpper();
                    var s = Sse.Add(lo128, hi128);
                    s = Sse.Add(s, Sse.MoveHighToLow(s, s));
                    s = Sse.AddScalar(s, Sse.Shuffle(s, s, 0b_00_00_00_01));
                    float dist = s.ToScalar();

                    if (dist < probeDists[n - 1])
                        InsertSorted(probeIdx, probeDists, ci, dist, n);
                }
                return;
            }
#endif
            for (int ci = 0; ci < _k; ci++)
            {
                if (hasExcluded && (excluded[ci >> 6] & (1UL << (ci & 63))) != 0) continue;

                float d = 0;
                float* c = cPtr + ci * 16;
                for (int dim = 0; dim < 14; dim++) { float diff = queryF[dim] - c[dim]; d += diff * diff; }

                if (d < probeDists[n - 1])
                    InsertSorted(probeIdx, probeDists, ci, d, n);
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

    private unsafe int UpdateTopK(int* dptr, Span<int> best, Span<byte> bestLabels, int labelBase, int bound)
    {
        for (int i = 0; i < 8; i++)
        {
            int d = dptr[i];
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
        return bound;
    }

    // Returns false if partial-distance early exit fired (block can be skipped).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe bool ProcessAllDims(Block* block, short* q, int* dptr, int* dimOrder, int bound)
    {
        short* blockBase = (short*)block;
#if TARGET_X64
        if (Avx2.IsSupported)
        {
            var acc = Vector256<int>.Zero;
            for (int di = 0; di < 14; di++)
            {
                int d = dimOrder[di];
                var qv = Vector256.Create((int)q[d]);
                var v8 = Vector128.Load(blockBase + d * 8);
                var wide = Avx2.ConvertToVector256Int32(v8);
                var diff = Avx2.Subtract(wide, qv);
                acc = Avx2.Add(acc, Avx2.MultiplyLow(diff, diff));

                // Two partial-distance checkpoints. High-variance dims first → acc grows fast.
                // Both are mathematically safe: partial ≤ full distance (all diffs² ≥ 0).
                if ((di == 3 || di == 7) && bound < int.MaxValue)
                {
                    var cmp = Avx2.CompareGreaterThan(Vector256.Create(bound), acc);
                    if (Avx2.MoveMask(cmp.AsByte()) == 0) return false;
                }
            }
            Avx.Store(dptr, acc);
            return true;
        }
#endif
#if TARGET_ARM64
        if (AdvSimd.IsSupported)
        {
            var acc_lo = Vector128<int>.Zero;
            var acc_hi = Vector128<int>.Zero;
            for (int di = 0; di < 14; di++)
            {
                int d = dimOrder[di];
                var qv = Vector128.Create((int)q[d]);
                var v8 = AdvSimd.LoadVector128(blockBase + d * 8);
                var lo = AdvSimd.SignExtendWideningLower(v8.GetLower());
                var hi = AdvSimd.SignExtendWideningUpper(v8);
                var dlo = AdvSimd.Subtract(lo, qv);
                var dhi = AdvSimd.Subtract(hi, qv);
                acc_lo = AdvSimd.Add(acc_lo, AdvSimd.Multiply(dlo, dlo));
                acc_hi = AdvSimd.Add(acc_hi, AdvSimd.Multiply(dhi, dhi));
            }
            AdvSimd.Store(dptr,     acc_lo);
            AdvSimd.Store(dptr + 4, acc_hi);
            return true;
        }
#endif
        for (int i = 0; i < 8; i++) dptr[i] = 0;
        for (int di = 0; di < 14; di++)
        {
            int d = dimOrder[di];
            int qd = q[d];
            short* dd = blockBase + d * 8;
            for (int i = 0; i < 8; i++) { int diff = dd[i] - qd; dptr[i] += diff * diff; }
        }
        return true;
    }
}
