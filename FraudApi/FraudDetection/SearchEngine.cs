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

    [SkipLocalsInit]
    public int Search(Span<short> query)
    {
        Span<float> queryF = stackalloc float[16];
        for (int d = 0; d < 14; d++) queryF[d] = query[d];

        Span<int> probeIdx = stackalloc int[_nprobe];
        Span<float> probeDists = stackalloc float[_nprobe];
        probeDists.Fill(float.MaxValue);
        FindNearestClusters(queryF, probeIdx, probeDists, ReadOnlySpan<ulong>.Empty);

        Span<long> best = stackalloc long[5];
        Span<byte> bestLabels = stackalloc byte[5];
        best.Fill(long.MaxValue);
        long bound = long.MaxValue;

        Span<short> queryOrd = stackalloc short[16];
        for (int di = 0; di < 14; di++) queryOrd[di] = query[_dimOrder[di]];

        fixed (short* qOrdPtr = queryOrd)
        {
            ScanProbes(qOrdPtr, queryOrd, probeIdx, ref bound, best, bestLabels);

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
                    ScanProbes(qOrdPtr, queryOrd, retryIdx, ref bound, best, bestLabels);
                }
            }
        }

        int count = 0;
        for (int i = 0; i < 5; i++) count += bestLabels[i];
        return count;
    }

    [SkipLocalsInit]
    private void ScanProbes(short* qPtr, Span<short> query, Span<int> probeIdx,
        ref long bound, Span<long> best, Span<byte> bestLabels)
    {
        int n = probeIdx.Length;
        // Align to 32 bytes so AVX2 store/load never fault on aligned variants.
        long* dptrRaw = stackalloc long[16];
        long* dptr = (long*)(((nint)dptrRaw + 31) & ~31);
        for (int pi = 0; pi < n; pi++)
        {
            int ci = probeIdx[pi];
            if (bound < long.MaxValue && BboxExceedsOrEquals(query, ci, bound)) continue;

            int bStart = _clusterBlockStart[ci];
            int bEnd   = bStart + _clusterBlockLen[ci];
            for (int b = bStart; b < bEnd; b++)
            {
                if (Sse.IsSupported && b + 8 < bEnd)
                    Sse.Prefetch0(_blocks + b + 8);

                if (!ProcessAllDims(_blocks + b, qPtr, dptr, bound)) continue;
                bound = UpdateTopK(dptr, best, bestLabels, b * 8, bound);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private bool BboxExceedsOrEquals(Span<short> query, int ci, long bound)
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe long UpdateTopK(long* dptr, Span<long> best, Span<byte> bestLabels, int labelBase, long bound)
    {
        for (int i = 0; i < 8; i++)
        {
            long d = dptr[i];
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
    // q and blockBase are both in variance order (reordered at call site once per query).
    // Accumulates into long to avoid int32 overflow: max dist = 14 * (2*Scale)^2 = 5.6e9 > int.MaxValue.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [SkipLocalsInit]
    private static unsafe bool ProcessAllDims(Block* block, short* q, long* dptr, long bound)
    {
        short* blockBase = (short*)block;
#if TARGET_X64
        if (Avx2.IsSupported)
        {
            var acc0 = Vector256<long>.Zero; // vecs 0-3
            var acc1 = Vector256<long>.Zero; // vecs 4-7
            for (int di = 0; di < 14; di++)
            {
                var qv = Vector256.Create((int)q[di]);
                var v8 = Vector128.Load(blockBase + di * 8);
                var wide = Avx2.ConvertToVector256Int32(v8);
                var diff = Avx2.Subtract(wide, qv);
                var sq = Avx2.MultiplyLow(diff, diff); // int32 squares (each fits: max 4e8 < int.MaxValue)
                acc0 = Avx2.Add(acc0, Avx2.ConvertToVector256Int64(sq.GetLower()));
                acc1 = Avx2.Add(acc1, Avx2.ConvertToVector256Int64(sq.GetUpper()));

                // Two partial-distance checkpoints. High-variance dims first → acc grows fast.
                if ((di == 3 || di == 7) && bound < long.MaxValue)
                {
                    var bv = Vector256.Create(bound);
                    var any = Avx2.Or(
                        Avx2.CompareGreaterThan(bv, acc0),
                        Avx2.CompareGreaterThan(bv, acc1));
                    if (Avx2.MoveMask(any.AsByte()) == 0) return false;
                }
            }
            Avx.Store(dptr,     acc0);
            Avx.Store(dptr + 4, acc1);
            return true;
        }
#endif
#if TARGET_ARM64
        if (AdvSimd.IsSupported)
        {
            var acc0 = Vector128<long>.Zero; // vecs 0-1
            var acc1 = Vector128<long>.Zero; // vecs 2-3
            var acc2 = Vector128<long>.Zero; // vecs 4-5
            var acc3 = Vector128<long>.Zero; // vecs 6-7
            for (int di = 0; di < 14; di++)
            {
                var qv = Vector128.Create((int)q[di]);
                var v8 = AdvSimd.LoadVector128(blockBase + di * 8);
                var lo = AdvSimd.SignExtendWideningLower(v8.GetLower());
                var hi = AdvSimd.SignExtendWideningUpper(v8);
                var dlo = AdvSimd.Subtract(lo, qv);
                var dhi = AdvSimd.Subtract(hi, qv);
                var sqlo = AdvSimd.Multiply(dlo, dlo);
                var sqhi = AdvSimd.Multiply(dhi, dhi);
                acc0 = AdvSimd.Add(acc0, AdvSimd.SignExtendWideningLower(sqlo));
                acc1 = AdvSimd.Add(acc1, AdvSimd.SignExtendWideningUpper(sqlo));
                acc2 = AdvSimd.Add(acc2, AdvSimd.SignExtendWideningLower(sqhi));
                acc3 = AdvSimd.Add(acc3, AdvSimd.SignExtendWideningUpper(sqhi));
            }
            AdvSimd.Store(dptr,     acc0);
            AdvSimd.Store(dptr + 2, acc1);
            AdvSimd.Store(dptr + 4, acc2);
            AdvSimd.Store(dptr + 6, acc3);
            return true;
        }
#endif
        for (int i = 0; i < 8; i++) dptr[i] = 0;
        for (int di = 0; di < 14; di++)
        {
            long qd = q[di];
            short* dd = blockBase + di * 8;
            for (int i = 0; i < 8; i++) { long diff = dd[i] - qd; dptr[i] += diff * diff; }
        }
        return true;
    }
}
