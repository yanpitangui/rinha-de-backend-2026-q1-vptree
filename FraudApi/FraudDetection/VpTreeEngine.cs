using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using FraudApi.Shared;

namespace FraudApi.FraudDetection;

// 64 bytes = exactly 1 cache line.
// Internal nodes: Vp[] + VpLabel + Threshold + Left + Right all in one fetch.
// Leaf nodes: Right=-1, Left=blockStart, VpIdxOrCount=blockCount; Vp[]/VpLabel/Threshold unused.
[StructLayout(LayoutKind.Sequential, Pack = 2, Size = 64)]
public unsafe struct VpNode
{
    public int   Left;          // internal: left child idx;  leaf: blockStart
    public int   Right;         // internal: right child idx; leaf: -1
    public float Threshold;     // internal: mu (normalized linear dist)
    public byte  VpLabel;       // internal: fraud label of vantage point
    public byte  BlockCountHi;  // leaf: high byte of blockCount (low byte in Left.high16 — unused; just use VpIdxOrCount)
    public int   VpIdxOrCount;  // leaf: blockCount (reuse field)
    public fixed short Vp[14];  // internal: VP vector (variance-ordered, int16)
    // Total used: 4+4+4+1+1+4+28 = 46 bytes → padded to 64 by Size=64
}

public sealed unsafe class VpTreeEngine
{
    private const float InvScale = 1.0f / Vectorizer.Scale;

    private readonly VpNode* _nodes;
    private readonly Block*  _leafBlocks;  // leafBlockCount × Block (column-major 8-wide)
    private readonly byte*   _leafLabels;  // leafBlockCount × 8 bytes
    private readonly int[]   _dimOrder;

    public VpTreeEngine(VpNode* nodes, Block* leafBlocks, byte* leafLabels, int[] dimOrder)
    {
        _nodes      = nodes;
        _leafBlocks = leafBlocks;
        _leafLabels = leafLabels;
        _dimOrder   = dimOrder;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query)
    {
        Span<short> q = stackalloc short[16];
        for (int di = 0; di < 14; di++) q[di] = query[_dimOrder[di]];
        q[14] = 0; q[15] = 0; // padding for 16-wide SIMD DistNorm

        Span<float> qf = stackalloc float[16];
        for (int di = 0; di < 14; di++) qf[di] = q[di] * InvScale;

        var heap = new KnnHeap5();
        fixed (short* qp = q)
        fixed (float* qfp = qf)
        {
            // Explicit stack — avoids ~23 recursive call frames per query.
            // Each entry: (nodeIdx, minDistSq). Skip entry if minDistSq > heap.Worst (sq).
            // Far side pushed first (with gap² as minDistSq), near side second (0),
            // so near side is processed first (LIFO). Lazy pruning on pop.
            StackEntry* stack = stackalloc StackEntry[64];
            int top = 0;
            stack[top++] = new StackEntry(0, 0f);

            while (top > 0)
            {
                StackEntry e = stack[--top];
                if (e.MinDistSq > heap.Worst) continue;

                VpNode* node = _nodes + e.NodeIdx;

                if (node->Right == -1)
                {
                    ScanLeafBlocks(qfp, node->Left, node->VpIdxOrCount, ref heap);
                    continue;
                }

                float vpDist = DistNorm(qp, node->Vp);
                heap.TryAdd(vpDist, node->VpLabel);

                float mu = node->Threshold;
                int near, far;
                float gap;
                if (vpDist <= mu) { near = node->Left;  far = node->Right; gap = mu - vpDist; }
                else              { near = node->Right; far = node->Left;  gap = vpDist - mu; }

                Sse.Prefetch0(_nodes + near);

                stack[top++] = new StackEntry(far,  gap * gap);
                stack[top++] = new StackEntry(near, 0f);
            }
        }
        return heap.FraudCount;
    }

    [SkipLocalsInit]
    private void ScanLeafBlocks(float* qf, int blockStart, int blockCount, ref KnnHeap5 heap)
    {
        float* dptr    = stackalloc float[8];
        float  boundSq = heap.Worst; // heap.Worst is already dist²

        for (int bi = 0; bi < blockCount; bi++)
        {
            Block* block = _leafBlocks + blockStart + bi;
            if (!ProcessBlock(block, qf, dptr, boundSq)) continue;

            byte* labels = _leafLabels + ((long)(blockStart + bi) << 3);
            for (int i = 0; i < 8; i++)
            {
                float dsq = dptr[i];
                if (dsq >= boundSq) continue;
                heap.TryAddSq(dsq, labels[i]);
                boundSq = heap.Worst;
            }
        }
    }

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float DistNorm(short* q, short* v)
    {
        // One 256-bit pass over 16 shorts (14 dims + 2 zeros in padding)
        var d    = Avx2.Subtract(Vector256.Load(q), Vector256.Load(v));
        var acc8 = Avx2.MultiplyAddAdjacent(d, d); // 8 × int32
        var sum4 = Sse2.Add(acc8.GetLower(), acc8.GetUpper());
        var s2   = Sse2.Add(sum4, Sse2.Shuffle(sum4, 0b_01_00_11_10));
        var s1   = Sse2.Add(s2,   Sse2.Shuffle(s2,   0b_10_11_00_01));
        return MathF.Sqrt((float)s1.GetElement(0)) * InvScale;
    }
}

public unsafe struct KnnHeap5
{
    private fixed float _d[5]; // squared distances
    private fixed byte  _l[5];
    private int _count;

    // Returns max dist² in heap (float.MaxValue when not full).
    // Used directly as boundSq — no multiply needed.
    public float Worst => _count < 5 ? float.MaxValue : _d[0];

    // For VP node adds: squares d internally so callers keep linear-dist semantics.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void TryAdd(float d, byte lbl) => TryAddSq(d * d, lbl);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void TryAddSq(float dsq, byte lbl)
    {
        if (_count < 5)
        {
            _d[_count] = dsq; _l[_count] = lbl;
            if (++_count == 5) BuildHeap();
            return;
        }
        if (dsq >= _d[0]) return;
        _d[0] = dsq; _l[0] = lbl;
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

internal readonly struct StackEntry
{
    public readonly int   NodeIdx;
    public readonly float MinDistSq;
    public StackEntry(int nodeIdx, float minDistSq) { NodeIdx = nodeIdx; MinDistSq = minDistSq; }
}
