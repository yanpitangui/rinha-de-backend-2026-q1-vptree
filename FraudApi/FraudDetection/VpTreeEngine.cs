using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using FraudApi.Shared;

namespace FraudApi.FraudDetection;

[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct VpNode
{
    public int   VpIdxOrCount; // internal: index into vpVecs array; leaf: block count
    public float Threshold;    // internal: partition distance mu (normalized linear)
    public int   Left;         // internal: left child node idx; leaf: blockStart
    public int   Right;        // internal: right child node idx; leaf: -1
}

public sealed unsafe class VpTreeEngine
{
    private const float InvScale = 1.0f / Vectorizer.Scale;

    private readonly VpNode* _nodes;
    private readonly short*  _vpVecs;     // internalCount × 14, row-major, variance-ordered
    private readonly byte*   _vpLabels;   // internalCount bytes
    private readonly Block*  _leafBlocks; // leafBlockCount × Block (column-major 8-wide)
    private readonly byte*   _leafLabels; // leafBlockCount × 8 bytes
    private readonly int[]   _dimOrder;

    public VpTreeEngine(
        VpNode* nodes, short* vpVecs, byte* vpLabels,
        Block* leafBlocks, byte* leafLabels,
        int[] dimOrder)
    {
        _nodes      = nodes;
        _vpVecs     = vpVecs;
        _vpLabels   = vpLabels;
        _leafBlocks = leafBlocks;
        _leafLabels = leafLabels;
        _dimOrder   = dimOrder;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query)
    {
        // Reorder query dims by variance (high→low) — matches stored vector dim order
        Span<short> q = stackalloc short[16];
        for (int di = 0; di < 14; di++) q[di] = query[_dimOrder[di]];

        // Pre-compute float query for AVX2 leaf scan
        Span<float> qf = stackalloc float[16];
        for (int di = 0; di < 14; di++) qf[di] = q[di] * InvScale;

        var heap = new KnnHeap5();
        fixed (short* qp = q)
        fixed (float* qfp = qf)
            SearchNode(0, qp, qfp, ref heap);
        return heap.FraudCount;
    }

    private void SearchNode(int nodeIdx, short* q, float* qf, ref KnnHeap5 heap)
    {
        VpNode* node = _nodes + nodeIdx;

        if (node->Right == -1)
        {
            ScanLeafBlocks(qf, node->Left, node->VpIdxOrCount, ref heap);
            return;
        }

        // Internal node: compute dist to vantage point (scalar, linear)
        int    vpIdx  = node->VpIdxOrCount;
        float  vpDist = DistNorm(q, _vpVecs + (long)vpIdx * 14);
        heap.TryAdd(vpDist, _vpLabels[vpIdx]);

        float mu  = node->Threshold;
        float tau = heap.Worst;

        if (vpDist <= mu)
        {
            SearchNode(node->Left, q, qf, ref heap);
            tau = heap.Worst;
            if (mu - vpDist <= tau)
                SearchNode(node->Right, q, qf, ref heap);
        }
        else
        {
            SearchNode(node->Right, q, qf, ref heap);
            tau = heap.Worst;
            if (vpDist - mu <= tau)
                SearchNode(node->Left, q, qf, ref heap);
        }
    }

    // AVX2 leaf scan: process 8 vectors per block, early-exit via bound check
    [SkipLocalsInit]
    private void ScanLeafBlocks(float* qf, int blockStart, int blockCount, ref KnnHeap5 heap)
    {
        float* dptr    = stackalloc float[8];
        float  boundSq = heap.Worst < float.MaxValue ? heap.Worst * heap.Worst : float.MaxValue;

        for (int bi = 0; bi < blockCount; bi++)
        {
            Block* block = _leafBlocks + blockStart + bi;
            if (Sse.IsSupported && bi + 4 < blockCount)
                Sse.Prefetch0(_leafBlocks + blockStart + bi + 4);

            if (!ProcessBlock(block, qf, dptr, boundSq)) continue;

            byte* labels = _leafLabels + ((long)(blockStart + bi) << 3);
            for (int i = 0; i < 8; i++)
            {
                float dsq = dptr[i];
                if (dsq >= boundSq) continue;
                float d = MathF.Sqrt(dsq);
                heap.TryAdd(d, labels[i]);
                if (heap.Worst < float.MaxValue)
                    boundSq = heap.Worst * heap.Worst;
            }
        }
    }

    // Compute squared distance (normalized float) for all 8 lanes in a column-major Block.
    // Returns false if ALL 8 lanes exceed boundSq at a partial-dim checkpoint → skip block.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [SkipLocalsInit]
    private static bool ProcessBlock(Block* block, float* qf, float* dptr, float boundSq)
    {
        short* blockBase = (short*)block;

        if (Avx2.IsSupported)
        {
            var scale = Vector256.Create(InvScale);
            var acc   = Vector256<float>.Zero;

            for (int di = 0; di < 14; di++)
            {
                var qv  = Vector256.Create(qf[di]);
                var v8  = Vector128.Load(blockBase + di * 8);
                var vf  = Avx.Multiply(Avx.ConvertToVector256Single(Avx2.ConvertToVector256Int32(v8)), scale);
                var dif = Avx.Subtract(vf, qv);
                acc = Fma.IsSupported
                    ? Fma.MultiplyAdd(dif, dif, acc)
                    : Avx.Add(acc, Avx.Multiply(dif, dif));

                if ((di == 3 || di == 7) && boundSq < float.MaxValue)
                {
                    if (Avx.MoveMask(Avx.CompareLessThan(acc, Vector256.Create(boundSq))) == 0)
                        return false;
                }
            }

            Avx.Store(dptr, acc);
            return true;
        }

        // Scalar fallback
        for (int i = 0; i < 8; i++) dptr[i] = 0f;
        for (int di = 0; di < 14; di++)
        {
            float  qd = qf[di];
            short* dd = blockBase + di * 8;
            for (int i = 0; i < 8; i++) { float d = dd[i] * InvScale - qd; dptr[i] += d * d; }
        }
        return true;
    }

    // Scalar linear distance for VP node lookups (called ~log(N) times per query)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float DistNorm(short* q, short* v)
    {
        long acc = 0;
        for (int d = 0; d < 14; d++) { int diff = q[d] - v[d]; acc += diff * diff; }
        return MathF.Sqrt((float)acc) * InvScale;
    }
}

public unsafe struct KnnHeap5
{
    private fixed float _d[5];
    private fixed byte  _l[5];
    private int _count;

    public float Worst => _count < 5 ? float.MaxValue : _d[0];

    public void TryAdd(float d, byte lbl)
    {
        if (_count < 5)
        {
            _d[_count] = d; _l[_count] = lbl;
            if (++_count == 5) BuildHeap();
            return;
        }
        if (d >= _d[0]) return;
        _d[0] = d; _l[0] = lbl;
        SiftDown(0);
    }

    private void BuildHeap() { SiftDown(1); SiftDown(0); }

    private void SiftDown(int i)
    {
        while (true)
        {
            int lg = i, l = 2 * i + 1, r = 2 * i + 2;
            if (l < _count && _d[l] > _d[lg]) lg = l;
            if (r < _count && _d[r] > _d[lg]) lg = r;
            if (lg == i) break;
            float td = _d[i]; _d[i] = _d[lg]; _d[lg] = td;
            byte  tl = _l[i]; _l[i] = _l[lg]; _l[lg] = tl;
            i = lg;
        }
    }

    public int FraudCount { get { int c = 0; for (int i = 0; i < 5; i++) c += _l[i]; return c; } }
}
