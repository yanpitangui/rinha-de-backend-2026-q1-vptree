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
    public byte  BlockCountHi;  // unused padding byte
    public int   VpIdxOrCount;  // leaf: blockCount (reuse field)
    public fixed short Vp[14];  // internal: VP vector (variance-ordered, int16)
    // Total used: 4+4+4+1+1+4+28 = 46 bytes padded to 64 by Size=64
}

public sealed unsafe class VpTreeEngine
{
    internal const float InvScale = 1.0f / Vectorizer.Scale;

    private readonly VpNode* _nodes;
    private readonly Block*  _leafBlocks;
    private readonly byte*   _leafLabels;
    private readonly int[]   _dimOrder;

    public VpTreeEngine(VpNode* nodes, Block* leafBlocks, byte* leafLabels, int[] dimOrder)
    {
        _nodes      = nodes;
        _leafBlocks = leafBlocks;
        _leafLabels = leafLabels;
        _dimOrder   = dimOrder;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query, Span<float> queryFloat = default)
    {
        Span<short> q = stackalloc short[16];
        for (int di = 0; di < 14; di++) q[di] = query[_dimOrder[di]];
        q[14] = 0; q[15] = 0;

        Span<float> qf = stackalloc float[16];
        if (!queryFloat.IsEmpty)
            for (int di = 0; di < 14; di++) qf[di] = queryFloat[_dimOrder[di]];
        else
            for (int di = 0; di < 14; di++) qf[di] = q[di] * InvScale;

        var heap = new KnnHeap5();
        fixed (short* qp = q)
        fixed (float* qfp = qf)
            SearchInto(qp, qfp, ref heap);
        return heap.FraudCount;
    }

    // Called by SegmentedVpTreeEngine with pre-reordered query pointers and shared heap.
    [SkipLocalsInit]
    internal void SearchInto(short* qp, float* qfp, ref KnnHeap5 heap)
    {
        // Explicit stack -- avoids ~23 recursive call frames per query.
        // Far side pushed first (gap^2 as minDistSq), near side second (0) -> LIFO = near first.
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
                // Peek at next stack entry: if leaf, prefetch its first block to overlap transfer.
                if (top > 0)
                {
                    VpNode* peek = _nodes + stack[top - 1].NodeIdx;
                    if (peek->Right == -1)
                        Sse.Prefetch0(_leafBlocks + peek->Left);
                }
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

    [SkipLocalsInit]
    private void ScanLeafBlocks(float* qf, int blockStart, int blockCount, ref KnnHeap5 heap)
    {
        float* dptr    = stackalloc float[8];
        float  boundSq = heap.Worst;

        int prefetchLimit = Math.Min(blockCount, 4);
        for (int p = 0; p < prefetchLimit; p++)
            Sse.Prefetch0(_leafBlocks + blockStart + p);

        for (int bi = 0; bi < blockCount; bi++)
        {
            if (bi + 3 < blockCount)
                Sse.Prefetch0(_leafBlocks + blockStart + bi + 3);

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

                // Every 2 dims: partial sum is a valid lower bound -- reject block early.
                if ((di & 1) == 1 && di < 13 && boundSq < float.MaxValue)
                {
                    if (Avx.MoveMask(Avx.CompareLessThan(acc, Vector256.Create(boundSq))) == 0)
                        return false;
                }
            }

            Avx.Store(dptr, acc);
            return true;
        }

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
        var d    = Avx2.Subtract(Vector256.Load(q), Vector256.Load(v));
        var acc8 = Avx2.MultiplyAddAdjacent(d, d);
        var sum4 = Sse2.Add(acc8.GetLower(), acc8.GetUpper());
        var s2   = Sse2.Add(sum4, Sse2.Shuffle(sum4, 0b_01_00_11_10));
        var s1   = Sse2.Add(s2,   Sse2.Shuffle(s2,   0b_10_11_00_01));
        return MathF.Sqrt((float)s1.GetElement(0)) * InvScale;
    }
}

// Wraps 16 VP-trees partitioned by (has_last_tx, is_online, card_present, unknown_merchant).
// Routes each query to its matching segment, then checks other segments only when d_k^2 exceeds
// the guaranteed cross-segment minimum distance:
//   has_last_tx flip -> dims 5+6 both sentinel -> min dist^2 += 2.0
//   binary dim mismatch (is_online/card_present/unknown_merchant) -> min dist^2 += 1.0 each
public sealed unsafe class SegmentedVpTreeEngine
{
    private readonly VpTreeEngine[] _segs;
    private readonly int[]          _dimOrder;
    // _sortedNeighbors[s*15 .. s*15+14]: other segment indices sorted by ascending cross-dist[s,*]
    private readonly byte[]         _sortedNeighbors;
    private static readonly float[] s_crossDist = BuildCrossDistTable();

    public SegmentedVpTreeEngine(VpTreeEngine[] segs, int[] dimOrder)
    {
        _segs            = segs;
        _dimOrder        = dimOrder;
        _sortedNeighbors = BuildSortedNeighbors();
    }

    private static float[] BuildCrossDistTable()
    {
        var t = new float[16 * 16];
        for (int i = 0; i < 16; i++)
            for (int j = 0; j < 16; j++)
            {
                float d = 0;
                if (((i ^ j) & 8) != 0) d += 2.0f; // has_last_tx: dims 5+6 both flip sentinel
                if (((i ^ j) & 4) != 0) d += 1.0f; // is_online
                if (((i ^ j) & 2) != 0) d += 1.0f; // card_present
                if (((i ^ j) & 1) != 0) d += 1.0f; // unknown_merchant
                t[i * 16 + j] = d;
            }
        return t;
    }

    private byte[] BuildSortedNeighbors()
    {
        var result = new byte[16 * 15];
        for (int s = 0; s < 16; s++)
        {
            var others = new (float dist, byte idx)[15];
            int k = 0;
            for (int t = 0; t < 16; t++)
                if (t != s) others[k++] = (s_crossDist[s * 16 + t], (byte)t);
            Array.Sort(others, (a, b) => a.dist.CompareTo(b.dist));
            for (int i = 0; i < 15; i++) result[s * 15 + i] = others[i].idx;
        }
        return result;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query, Span<float> queryFloat = default)
    {
        // Segment key from original-order query (before variance reordering).
        // bit3=has_last_tx (dim5!=-1), bit2=is_online (dim9=1), bit1=card_present (dim10=1), bit0=unknown_merchant (dim11=1)
        int segKey;
        if (!queryFloat.IsEmpty)
        {
            bool hasLastTx    = queryFloat[5] > -0.5f;
            bool isOnline     = queryFloat[9] > 0.5f;
            bool cardPresent  = queryFloat[10] > 0.5f;
            bool unknownMerch = queryFloat[11] > 0.5f;
            segKey = (hasLastTx ? 8 : 0) | (isOnline ? 4 : 0) | (cardPresent ? 2 : 0) | (unknownMerch ? 1 : 0);
        }
        else
        {
            // query[5] sentinel = -10000; binary dims are 0 or 10000
            bool hasLastTx    = query[5] > -5000;
            bool isOnline     = query[9] > 5000;
            bool cardPresent  = query[10] > 5000;
            bool unknownMerch = query[11] > 5000;
            segKey = (hasLastTx ? 8 : 0) | (isOnline ? 4 : 0) | (cardPresent ? 2 : 0) | (unknownMerch ? 1 : 0);
        }

        // Reorder query dims once (all 16 trees share the same dimOrder).
        Span<short> q = stackalloc short[16];
        for (int di = 0; di < 14; di++) q[di] = query[_dimOrder[di]];
        q[14] = 0; q[15] = 0;

        Span<float> qf = stackalloc float[16];
        if (!queryFloat.IsEmpty)
            for (int di = 0; di < 14; di++) qf[di] = queryFloat[_dimOrder[di]];
        else
            for (int di = 0; di < 14; di++) qf[di] = q[di] * VpTreeEngine.InvScale;

        var heap = new KnnHeap5();
        fixed (short* qp = q)
        fixed (float* qfp = qf)
        {
            _segs[segKey].SearchInto(qp, qfp, ref heap);

            // Check other segments in ascending cross-dist order.
            // heap.Worst only decreases; cross-dist only increases along sorted list -> safe early break.
            int sortBase = segKey * 15;
            for (int i = 0; i < 15; i++)
            {
                int s = _sortedNeighbors[sortBase + i];
                if (heap.Worst <= s_crossDist[segKey * 16 + s]) break;
                _segs[s].SearchInto(qp, qfp, ref heap);
            }
        }
        return heap.FraudCount;
    }
}

public unsafe struct KnnHeap5
{
    private fixed float _d[5]; // squared distances
    private fixed byte  _l[5];
    private int _count;

    // Returns max dist^2 in heap (float.MaxValue when not full).
    public float Worst => _count < 5 ? float.MaxValue : _d[0];

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
