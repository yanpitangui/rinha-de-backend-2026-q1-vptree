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
    private readonly float[] _centroids;
    private readonly int[] _clusterBlockStart;
    private readonly int[] _clusterBlockLen;

    public SearchEngine(
        Block* blocks, byte* labels,
        float[] centroids, int[] clusterBlockStart, int[] clusterBlockLen,
        int k, int nprobe)
    {
        _blocks = blocks;
        _labels = labels;
        _centroids = centroids;
        _clusterBlockStart = clusterBlockStart;
        _clusterBlockLen = clusterBlockLen;
        _k = k;
        _nprobe = nprobe;
    }

    public int Search(Span<short> query)
    {
        // Step 1: find the nprobe nearest centroids
        Span<int> probeIdx = stackalloc int[_nprobe];
        FindTopClusters(query, probeIdx);

        // Step 2: scan selected cluster blocks, maintain global top-5
        Span<int> best = stackalloc int[5];
        Span<byte> bestLabels = stackalloc byte[5];
        best.Fill(int.MaxValue);
        Span<int> dist = stackalloc int[64];

        fixed (short* qPtr = query)
        {
            for (int pi = 0; pi < _nprobe; pi++)
            {
                int ci = probeIdx[pi];
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
                    UpdateTopK(dist, best, bestLabels, b * 64);
                }
            }
        }

        int count = 0;
        for (int i = 0; i < 5; i++) count += bestLabels[i];
        return count;
    }

    private void FindTopClusters(Span<short> query, Span<int> probeIdx)
    {
        // L2 distance from query to every centroid (K=256 floats on stack = 1 KB)
        Span<float> dists = stackalloc float[_k];
        fixed (float* cPtr = _centroids)
        {
            for (int ci = 0; ci < _k; ci++)
            {
                float d = 0;
                float* c = cPtr + ci * 16;
                for (int dim = 0; dim < 14; dim++)
                {
                    float diff = query[dim] - c[dim];
                    d += diff * diff;
                }
                dists[ci] = d;
            }
        }

        // Pick nprobe smallest by linear scan (K=256 is tiny)
        Span<float> probeDists = stackalloc float[_nprobe];
        probeDists.Fill(float.MaxValue);
        probeIdx.Fill(0);

        for (int ci = 0; ci < _k; ci++)
        {
            float d = dists[ci];
            int worstIdx = 0;
            float worstDist = probeDists[0];
            for (int j = 1; j < _nprobe; j++)
            {
                if (probeDists[j] > worstDist) { worstDist = probeDists[j]; worstIdx = j; }
            }
            if (d < worstDist)
            {
                probeDists[worstIdx] = d;
                probeIdx[worstIdx] = ci;
            }
        }
    }

    private unsafe void UpdateTopK(Span<int> dist, Span<int> best, Span<byte> bestLabels, int labelBase)
    {
        for (int i = 0; i < 64; i++)
        {
            int d = dist[i];
            int maxIdx = 0, maxVal = best[0];
            for (int j = 1; j < 5; j++)
            {
                if (best[j] > maxVal) { maxVal = best[j]; maxIdx = j; }
            }
            if (d < maxVal)
            {
                best[maxIdx] = d;
                bestLabels[maxIdx] = _labels[labelBase + i];
            }
        }
    }

    private static unsafe void ProcessDim(short* data, short q, Span<int> dist)
    {
        fixed (int* dptr = dist)
        {
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

            for (int i = 0; i < 64; i++)
            {
                int d = data[i] - q;
                dptr[i] += d * d;
            }
        }
    }
}
