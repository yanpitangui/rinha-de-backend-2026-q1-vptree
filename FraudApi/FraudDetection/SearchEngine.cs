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
    private readonly float[] _centroids;
    private readonly int[] _clusterBlockStart;
    private readonly int[] _clusterBlockLen;
    private readonly short* _bboxMin;
    private readonly short* _bboxMax;

    public SearchEngine(
        Block* blocks, byte* labels,
        float[] centroids, int[] clusterBlockStart, int[] clusterBlockLen,
        short* bboxMin, short* bboxMax,
        int k, int nprobe, int nprobeRetry)
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
    }

    public int Search(Span<short> query)
    {
        // Pre-convert query to float once — reused for all centroid distance calls
        Span<float> queryF = stackalloc float[16];
        for (int d = 0; d < 14; d++) queryF[d] = query[d];

        // Find nprobe nearest clusters, already sorted ascending by distance
        Span<int> probeIdx = stackalloc int[_nprobe];
        Span<float> probeDists = stackalloc float[_nprobe];
        probeDists.Fill(float.MaxValue);
        FindNearestClusters(queryF, probeIdx, probeDists, ReadOnlySpan<ulong>.Empty);

        Span<int> best = stackalloc int[5];
        Span<byte> bestLabels = stackalloc byte[5];
        best.Fill(int.MaxValue);
        int bound = int.MaxValue;
        Span<int> dist = stackalloc int[64];

        fixed (short* qPtr = query)
        {
            ScanProbes(qPtr, query, probeIdx, ref bound, best, bestLabels, dist);

            if (_nprobeRetry > 0)
            {
                int fc = 0;
                for (int i = 0; i < 5; i++) fc += bestLabels[i];

                // Borderline: fc=2 (score=0.4, approved but close) or fc=3 (score=0.6, rejected threshold)
                if (fc == 2 || fc == 3)
                {
                    int words = (_k + 63) >> 6;
                    Span<ulong> visited = stackalloc ulong[words];
                    visited.Clear();
                    for (int i = 0; i < _nprobe; i++)
                        visited[probeIdx[i] >> 6] |= 1UL << (probeIdx[i] & 63);

                    Span<int> retryIdx = stackalloc int[_nprobeRetry];
                    Span<float> retryDists = stackalloc float[_nprobeRetry];
                    retryDists.Fill(float.MaxValue);
                    FindNearestClusters(queryF, retryIdx, retryDists, visited);
                    ScanProbes(qPtr, query, retryIdx, ref bound, best, bestLabels, dist);
                }
            }
        }

        int count = 0;
        for (int i = 0; i < 5; i++) count += bestLabels[i];
        return count;
    }

    private void ScanProbes(short* qPtr, Span<short> query, Span<int> probeIdx, ref int bound, Span<int> best, Span<byte> bestLabels, Span<int> dist)
    {
        int n = probeIdx.Length;
        for (int pi = 0; pi < n; pi++)
        {
            int ci = probeIdx[pi];

            // Skip cluster if its bbox is provably farther than current best
            if (bound < int.MaxValue && BboxExceedsOrEquals(query, ci, bound)) continue;

            int bEnd = _clusterBlockStart[ci] + _clusterBlockLen[ci];
            for (int b = _clusterBlockStart[ci]; b < bEnd; b++)
            {
                dist.Clear();
                Block* block = _blocks + b;
                ProcessDim(block->D0,  qPtr[0],  dist);
                ProcessDim(block->D1,  qPtr[1],  dist);
                ProcessDim(block->D2,  qPtr[2],  dist);
                ProcessDim(block->D3,  qPtr[3],  dist);
                ProcessDim(block->D4,  qPtr[4],  dist);
                ProcessDim(block->D5,  qPtr[5],  dist);
                ProcessDim(block->D6,  qPtr[6],  dist);
                ProcessDim(block->D7,  qPtr[7],  dist);
                ProcessDim(block->D8,  qPtr[8],  dist);
                ProcessDim(block->D9,  qPtr[9],  dist);
                ProcessDim(block->D10, qPtr[10], dist);
                ProcessDim(block->D11, qPtr[11], dist);
                ProcessDim(block->D12, qPtr[12], dist);
                ProcessDim(block->D13, qPtr[13], dist);
                bound = UpdateTopK(dist, best, bestLabels, b * 64, bound);
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

    // Finds the n nearest cluster centroids to queryF (already as float).
    // Excluded bitset: skip any cluster with its bit set (used for retry pass).
    // Results are maintained in sorted ascending order (nearest first).
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
                var qv0 = Avx.LoadVector256(qfPtr);      // dims 0-7
                var qv1 = Avx.LoadVector256(qfPtr + 8);  // dims 8-15 (14,15 = 0.0 padding in centroids)

                for (int ci = 0; ci < _k; ci++)
                {
                    if (hasExcluded && (excluded[ci >> 6] & (1UL << (ci & 63))) != 0) continue;

                    float* c = cPtr + ci * 16;
                    var d0 = Avx.Subtract(qv0, Avx.LoadVector256(c));
                    var d1 = Avx.Subtract(qv1, Avx.LoadVector256(c + 8));
                    d0 = Avx.Multiply(d0, d0);
                    d1 = Avx.Multiply(d1, d1);
                    var sum = Avx.Add(d0, d1);
                    // Horizontal sum of 8 floats → scalar
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

    private unsafe int UpdateTopK(Span<int> dist, Span<int> best, Span<byte> bestLabels, int labelBase, int bound)
    {
        for (int i = 0; i < 64; i++)
        {
            int d = dist[i];
            if (d > bound) continue;

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

    private static unsafe void ProcessDim(short* data, short q, Span<int> dist)
    {
        fixed (int* dptr = dist)
        {
#if TARGET_X64
            if (Avx2.IsSupported)
            {
                var qVec = Vector256.Create((int)q);
                for (int i = 0; i < 64; i += 16)
                {
                    var v = Avx.LoadVector256(data + i);
                    var lo = Avx2.ConvertToVector256Int32(v.GetLower());
                    var hi = Avx2.ConvertToVector256Int32(v.GetUpper());
                    var dlo = Avx2.Subtract(lo, qVec);
                    var dhi = Avx2.Subtract(hi, qVec);
                    var sqLo = Avx2.MultiplyLow(dlo, dlo);
                    var sqHi = Avx2.MultiplyLow(dhi, dhi);
                    Avx.Store(dptr + i,     Avx2.Add(Avx.LoadVector256(dptr + i),     sqLo));
                    Avx.Store(dptr + i + 8, Avx2.Add(Avx.LoadVector256(dptr + i + 8), sqHi));
                }
                return;
            }
#endif
#if TARGET_ARM64
            if (AdvSimd.IsSupported)
            {
                var qVec = Vector128.Create((int)q);
                for (int i = 0; i < 64; i += 8)
                {
                    var v = AdvSimd.LoadVector128(data + i);
                    var lo = AdvSimd.SignExtendWideningLower(v.GetLower());
                    var hi = AdvSimd.SignExtendWideningUpper(v);
                    var dlo = AdvSimd.Subtract(lo, qVec);
                    var dhi = AdvSimd.Subtract(hi, qVec);
                    var sqLo = AdvSimd.Multiply(dlo, dlo);
                    var sqHi = AdvSimd.Multiply(dhi, dhi);
                    AdvSimd.Store(dptr + i,     AdvSimd.Add(AdvSimd.LoadVector128(dptr + i),     sqLo));
                    AdvSimd.Store(dptr + i + 4, AdvSimd.Add(AdvSimd.LoadVector128(dptr + i + 4), sqHi));
                }
                return;
            }
#endif
            for (int i = 0; i < 64; i++)
            {
                int d = data[i] - q;
                dptr[i] += d * d;
            }
        }
    }
}
