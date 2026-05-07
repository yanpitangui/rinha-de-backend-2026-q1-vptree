using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using FraudApi.Shared;

namespace FraudApi.FraudDetection;

public unsafe class SearchEngine
{
    private readonly Block* _blocks;
    private readonly byte* _labels;
    private readonly int _blockCount;

    public SearchEngine(Block* blocks, byte* labels, int blockCount)
    {
        _blocks = blocks;
        _labels = labels;
        _blockCount = blockCount;
    }

    public int Search(Span<short> query)
    {
        Span<int> best = stackalloc int[5];
        Span<byte> bestLabels = stackalloc byte[5];

        // initialize best distances
        for (int i = 0; i < 5; i++)
            best[i] = int.MaxValue;

        for (int b = 0; b < _blockCount; b++)
        {
            ProcessBlock(ref _blocks[b], query, best, bestLabels, b);
        }

        return CountFraud(bestLabels);
    }

    private unsafe void ProcessBlock(
        ref Block block,
        Span<short> query,
        Span<int> best,
        Span<byte> bestLabels,
        int blockIndex)
    {
        Span<int> dist = stackalloc int[64];
        dist.Clear();

        fixed (Block* b = &block)
        {
            ProcessDim(b->D0,  query[0],  dist);
            ProcessDim(b->D1,  query[1],  dist);
            ProcessDim(b->D2,  query[2],  dist);
            ProcessDim(b->D3,  query[3],  dist);
            ProcessDim(b->D4,  query[4],  dist);
            ProcessDim(b->D5,  query[5],  dist);
            ProcessDim(b->D6,  query[6],  dist);
            ProcessDim(b->D7,  query[7],  dist);
            ProcessDim(b->D8,  query[8],  dist);
            ProcessDim(b->D9,  query[9],  dist);
            ProcessDim(b->D10, query[10], dist);
            ProcessDim(b->D11, query[11], dist);
            ProcessDim(b->D12, query[12], dist);
            ProcessDim(b->D13, query[13], dist);
        }

        UpdateTopK(dist, best, bestLabels, blockIndex);
    }

    private unsafe void ProcessDim(short* data, short q, Span<int> dist)
    {
        if (!Avx2.IsSupported)
        {
            // fallback (rare, but safe)
            for (int i = 0; i < 64; i++)
            {
                int d = data[i] - q;
                dist[i] += d * d;
            }
            return;
        }

        var qVec = Vector256.Create((int)q);

        fixed (int* dptr = dist)
        {
            for (int i = 0; i < 64; i += 16)
            {
                // load 16 shorts (256-bit)
                var v = Avx.LoadVector256(data + i);

                // split into 2x 128-bit halves
                var lo128 = v.GetLower();
                var hi128 = v.GetUpper();

                // widen short → int (8 lanes each)
                var lo = Avx2.ConvertToVector256Int32(lo128);
                var hi = Avx2.ConvertToVector256Int32(hi128);

                // subtract query
                var dlo = Avx2.Subtract(lo, qVec);
                var dhi = Avx2.Subtract(hi, qVec);

                // square (mul)
                var sqLo = Avx2.MultiplyLow(dlo, dlo);
                var sqHi = Avx2.MultiplyLow(dhi, dhi);

                // load current distances
                var accLo = Avx.LoadVector256(dptr + i);
                var accHi = Avx.LoadVector256(dptr + i + 8);

                // accumulate
                accLo = Avx2.Add(accLo, sqLo);
                accHi = Avx2.Add(accHi, sqHi);

                // store back
                Avx.Store(dptr + i, accLo);
                Avx.Store(dptr + i + 8, accHi);
            }
        }
    }

    private void UpdateTopK(
        Span<int> dist,
        Span<int> best,
        Span<byte> bestLabels,
        int blockIndex)
    {
        for (int i = 0; i < 64; i++)
        {
            int d = dist[i];

            // find current max in best[]
            int maxIdx = 0;
            int maxVal = best[0];

            for (int j = 1; j < 5; j++)
            {
                if (best[j] > maxVal)
                {
                    maxVal = best[j];
                    maxIdx = j;
                }
            }

            if (d < maxVal)
            {
                best[maxIdx] = d;
                bestLabels[maxIdx] = _labels[blockIndex * 64 + i];
            }
        }
    }

    private int CountFraud(Span<byte> labels)
    {
        int count = 0;

        for (int i = 0; i < 5; i++)
            count += labels[i];

        return count;
    }
}