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
        // Near child always has minDist=0 so is always visited -- skip push/pop, process directly.
        // Only push far child, and skip push if already prunable (farMinDist > heap.Worst).
        StackEntry* stack = stackalloc StackEntry[64];
        int top = 0;
        int curNode = 0;
        float curMin = 0f;

        while (true)
        {
            if (curMin > heap.Worst)
            {
                if (top == 0) break;
                StackEntry e = stack[--top];
                curNode = e.NodeIdx; curMin = e.MinDistSq;
                continue;
            }

            VpNode* node = _nodes + curNode;

            if (node->Right == -1)
            {
                // Peek at next stack entry: if leaf, prefetch its first blocks to overlap DRAM transfer.
                if (top > 0)
                {
                    VpNode* peek = _nodes + stack[top - 1].NodeIdx;
                    if (peek->Right == -1)
                    {
                        int peekBlocks = Math.Min(peek->VpIdxOrCount, 5);
                        for (int p = 0; p < peekBlocks; p++)
                            Sse.Prefetch0(_leafBlocks + peek->Left + p);
                    }
                }
                ScanLeafBlocks(qfp, node->Left, node->VpIdxOrCount, ref heap);
                if (top == 0) break;
                StackEntry le = stack[--top];
                curNode = le.NodeIdx; curMin = le.MinDistSq;
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

            float farMinDist = gap * gap;
            if (farMinDist <= heap.Worst)
                stack[top++] = new StackEntry(far, farMinDist);

            curNode = near;
            curMin = 0f;
        }
    }

    [SkipLocalsInit]
    private void ScanLeafBlocks(float* qf, int blockStart, int blockCount, ref KnnHeap5 heap)
    {
        float* dptr    = stackalloc float[16];
        float  boundSq = heap.Worst;

        int prefetchLimit = Math.Min(blockCount, 8);
        for (int p = 0; p < prefetchLimit; p++)
            Sse.Prefetch0(_leafBlocks + blockStart + p);

        for (int bi = 0; bi < blockCount; bi++)
        {
            if (bi + 7 < blockCount)
                Sse.Prefetch0(_leafBlocks + blockStart + bi + 7);

            Block* block = _leafBlocks + blockStart + bi;
            if (!ProcessBlock(block, qf, dptr, boundSq)) continue;

            // Skip heap update if all 16 final distances over bound.
            var bound256 = Vector256.Create(boundSq);
            if (Avx.MoveMask(Avx.CompareLessThan(Avx.LoadVector256(dptr),     bound256)) == 0 &&
                Avx.MoveMask(Avx.CompareLessThan(Avx.LoadVector256(dptr + 8), bound256)) == 0)
                continue;

            byte* labels = _leafLabels + ((long)(blockStart + bi) << 4);
            for (int i = 0; i < 16; i++)
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
            var scale  = Vector256.Create(InvScale);
            var acc_lo = Vector256<float>.Zero;
            var acc_hi = Vector256<float>.Zero;
            var bound  = Vector256.Create(boundSq);

            for (int di = 0; di < 14; di++)
            {
                var qv    = Vector256.Create(qf[di]);
                var v_lo  = Vector128.Load(blockBase + di * 16);
                var v_hi  = Vector128.Load(blockBase + di * 16 + 8);
                var vf_lo = Avx.Multiply(Avx.ConvertToVector256Single(Avx2.ConvertToVector256Int32(v_lo)), scale);
                var vf_hi = Avx.Multiply(Avx.ConvertToVector256Single(Avx2.ConvertToVector256Int32(v_hi)), scale);
                var d_lo  = Avx.Subtract(vf_lo, qv);
                var d_hi  = Avx.Subtract(vf_hi, qv);
                acc_lo = Fma.IsSupported
                    ? Fma.MultiplyAdd(d_lo, d_lo, acc_lo)
                    : Avx.Add(acc_lo, Avx.Multiply(d_lo, d_lo));
                acc_hi = Fma.IsSupported
                    ? Fma.MultiplyAdd(d_hi, d_hi, acc_hi)
                    : Avx.Add(acc_hi, Avx.Multiply(d_hi, d_hi));

                // Every 2 dims: partial sum is a valid lower bound -- reject block early.
                if ((di & 1) == 1 && di < 13 &&
                    Avx.MoveMask(Avx.CompareLessThan(acc_lo, bound)) == 0 &&
                    Avx.MoveMask(Avx.CompareLessThan(acc_hi, bound)) == 0)
                    return false;
            }

            Avx.Store(dptr,     acc_lo);
            Avx.Store(dptr + 8, acc_hi);
            return true;
        }

        for (int i = 0; i < 16; i++) dptr[i] = 0f;
        for (int di = 0; di < 14; di++)
        {
            float  qd = qf[di];
            short* dd = blockBase + di * 16;
            for (int i = 0; i < 16; i++) { float d = dd[i] * InvScale - qd; dptr[i] += d * d; }
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

// Wraps 16/17/32 VP-trees partitioned by binary dims + optional continuous splits per base segment.
public sealed unsafe class SegmentedVpTreeEngine
{
    private readonly VpTreeEngine[] _segs;
    private readonly int[]          _dimOrder;
    private readonly byte[]         _sortedNeighbors;
    private static readonly float[] s_crossDist16 = BuildCrossDistTable16();
    private static readonly float[] s_crossDist32 = BuildCrossDistTable32();
    // 32-seg: per-base-segment split spec (reordered dim, int16 threshold). null = legacy mode.
    private readonly (int DimReordered, short Threshold)[]? _splits32;
    // Legacy 17-seg split fields.
    private readonly int   _splitDimReordered;
    private readonly short _splitThreshold;
    // KD-routing mode: per-base routing trees. null = legacy/32-seg mode.
    private readonly RouteNodeRuntime[][]? _routeTrees;

    public SegmentedVpTreeEngine(VpTreeEngine[] segs, int[] dimOrder, int splitDim = -1, short splitThreshold = 0)
    {
        _segs            = segs;
        _dimOrder        = dimOrder;
        _sortedNeighbors = BuildSortedNeighbors16();
        if (splitDim >= 0 && segs.Length == 17)
        {
            var rev = new int[14];
            for (int di = 0; di < 14; di++) rev[dimOrder[di]] = di;
            _splitDimReordered = rev[splitDim];
            _splitThreshold    = splitThreshold;
        }
        else _splitDimReordered = -1;
    }

    public SegmentedVpTreeEngine(VpTreeEngine[] segs, int[] dimOrder, int[] splitDims, short[] splitThreshs)
    {
        _segs            = segs;
        _dimOrder        = dimOrder;
        _sortedNeighbors = BuildSortedNeighbors32();
        var rev = new int[14];
        for (int di = 0; di < 14; di++) rev[dimOrder[di]] = di;
        _splits32 = new (int, short)[16];
        for (int s = 0; s < 16; s++)
            _splits32[s] = (splitDims[s] >= 0 ? rev[splitDims[s]] : -1, splitThreshs[s]);
        _splitDimReordered = -1;
    }

    // KD-routing constructor: variable number of sub-segs with per-base routing trees.
    public SegmentedVpTreeEngine(VpTreeEngine[] segs, int[] dimOrder, RouteNodeRuntime[][] routeTrees)
    {
        _segs              = segs;
        _dimOrder          = dimOrder;
        _routeTrees        = routeTrees;
        _sortedNeighbors   = BuildSortedNeighbors16();
        _splitDimReordered = -1;
    }

    private static float[] BuildCrossDistTable16()
    {
        var t = new float[16 * 16];
        for (int i = 0; i < 16; i++)
            for (int j = 0; j < 16; j++)
            {
                float d = 0;
                if (((i ^ j) & 8) != 0) d += 2.0f;
                if (((i ^ j) & 4) != 0) d += 1.0f;
                if (((i ^ j) & 2) != 0) d += 1.0f;
                if (((i ^ j) & 1) != 0) d += 1.0f;
                t[i * 16 + j] = d;
            }
        return t;
    }

    private static float[] BuildCrossDistTable32()
    {
        var t = new float[32 * 32];
        for (int i = 0; i < 32; i++)
            for (int j = 0; j < 32; j++)
            {
                if (i % 16 == j % 16) { t[i * 32 + j] = 0f; continue; }
                int a = i % 16, b = j % 16;
                float d = 0;
                if (((a ^ b) & 8) != 0) d += 2.0f;
                if (((a ^ b) & 4) != 0) d += 1.0f;
                if (((a ^ b) & 2) != 0) d += 1.0f;
                if (((a ^ b) & 1) != 0) d += 1.0f;
                t[i * 32 + j] = d;
            }
        return t;
    }

    private static byte[] BuildSortedNeighbors16()
    {
        var result = new byte[16 * 15];
        for (int s = 0; s < 16; s++)
        {
            var others = new (float dist, byte idx)[15];
            int k = 0;
            for (int t = 0; t < 16; t++)
                if (t != s) others[k++] = (s_crossDist16[s * 16 + t], (byte)t);
            Array.Sort(others, (a, b) => a.dist.CompareTo(b.dist));
            for (int i = 0; i < 15; i++) result[s * 15 + i] = others[i].idx;
        }
        return result;
    }

    private static byte[] BuildSortedNeighbors32()
    {
        var result = new byte[32 * 30];
        for (int s = 0; s < 32; s++)
        {
            int partner = s < 16 ? s + 16 : s - 16;
            var others  = new (float dist, byte idx)[30];
            int k = 0;
            for (int t = 0; t < 32; t++)
                if (t != s && t != partner) others[k++] = (s_crossDist32[s * 32 + t], (byte)t);
            Array.Sort(others, (a, b) => a.dist.CompareTo(b.dist));
            for (int i = 0; i < 30; i++) result[s * 30 + i] = others[i].idx;
        }
        return result;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query, Span<float> queryFloat = default)
    {
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
            bool hasLastTx    = query[5] > -5000;
            bool isOnline     = query[9] > 5000;
            bool cardPresent  = query[10] > 5000;
            bool unknownMerch = query[11] > 5000;
            segKey = (hasLastTx ? 8 : 0) | (isOnline ? 4 : 0) | (cardPresent ? 2 : 0) | (unknownMerch ? 1 : 0);
        }

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
            if (_routeTrees != null)
                SearchKD(segKey, qp, qfp, ref heap);
            else if (_splits32 != null)
                Search32(segKey, qp, qfp, ref heap);
            else
                SearchLegacy(segKey, qp, qfp, ref heap);
        }
        return heap.FraudCount;
    }

    private void SearchKD(int segKey, short* qp, float* qfp, ref KnnHeap5 heap)
    {
        SearchBaseKD(segKey, qp, qfp, ref heap);
        int sortBase = segKey * 15;
        for (int i = 0; i < 15; i++)
        {
            int b = _sortedNeighbors[sortBase + i];
            if (s_crossDist16[segKey * 16 + b] >= heap.Worst) break;
            SearchBaseKD(b, qp, qfp, ref heap);
        }
    }

    [SkipLocalsInit]
    private void SearchBaseKD(int baseIdx, short* qp, float* qfp, ref KnnHeap5 heap)
    {
        var tree = _routeTrees![baseIdx];
        if (tree.Length == 0) return;
        fixed (RouteNodeRuntime* nodes = tree)
        {
            StackEntry* stack = stackalloc StackEntry[64];
            int top = 0, cur = 0; float curMin = 0f;
            while (true)
            {
                if (curMin > heap.Worst)
                {
                    if (top == 0) break;
                    StackEntry e = stack[--top]; cur = e.NodeIdx; curMin = e.MinDistSq;
                    continue;
                }
                RouteNodeRuntime* node = nodes + cur;
                if (node->DimReordered == -1)
                {
                    _segs[node->SegIdx].SearchInto(qp, qfp, ref heap);
                    if (top == 0) break;
                    StackEntry e = stack[--top]; cur = e.NodeIdx; curMin = e.MinDistSq;
                    continue;
                }
                float qd  = qfp[node->DimReordered];
                float thr = node->Threshold * VpTreeEngine.InvScale;
                float gap = qd - thr;
                int near  = gap <= 0f ? node->LoChild : node->HiChild;
                int far   = gap <= 0f ? node->HiChild : node->LoChild;
                float farMin = gap * gap;
                if (farMin <= heap.Worst) stack[top++] = new StackEntry(far, farMin);
                cur = near; curMin = 0f;
            }
        }
    }

    private void Search32(int segKey, short* qp, float* qfp, ref KnnHeap5 heap)
    {
        var split  = _splits32![segKey];
        int ownSeg = (split.DimReordered >= 0 && qp[split.DimReordered] > split.Threshold)
            ? 16 + segKey : segKey;
        _segs[ownSeg].SearchInto(qp, qfp, ref heap);

        if (split.DimReordered >= 0)
        {
            int   otherHalf = ownSeg < 16 ? ownSeg + 16 : ownSeg - 16;
            float gap       = MathF.Abs((float)(qp[split.DimReordered] - split.Threshold)) * VpTreeEngine.InvScale;
            if (heap.Worst > gap * gap)
                _segs[otherHalf].SearchInto(qp, qfp, ref heap);
        }

        int sortBase = ownSeg * 30;
        for (int i = 0; i < 30; i++)
        {
            int s = _sortedNeighbors[sortBase + i];
            if (s_crossDist32[ownSeg * 32 + s] >= heap.Worst) break;
            _segs[s].SearchInto(qp, qfp, ref heap);
        }
    }

    private void SearchLegacy(int segKey, short* qp, float* qfp, ref KnnHeap5 heap)
    {
        bool isSeg10 = segKey == 10 && _splitDimReordered >= 0;
        int  ownSeg  = segKey;
        if (isSeg10)
            ownSeg = qp[_splitDimReordered] > _splitThreshold ? 16 : 10;

        _segs[ownSeg].SearchInto(qp, qfp, ref heap);

        if (isSeg10)
        {
            int   otherSeg = ownSeg == 10 ? 16 : 10;
            float gap      = MathF.Abs((float)(qp[_splitDimReordered] - _splitThreshold)) * VpTreeEngine.InvScale;
            if (heap.Worst > gap * gap)
                _segs[otherSeg].SearchInto(qp, qfp, ref heap);
        }

        int sortBase = segKey * 15;
        for (int i = 0; i < 15; i++)
        {
            int s = _sortedNeighbors[sortBase + i];
            if (heap.Worst <= s_crossDist16[segKey * 16 + s]) break;
            if (s == 10 && _splitDimReordered >= 0)
            {
                _segs[10].SearchInto(qp, qfp, ref heap);
                _segs[16].SearchInto(qp, qfp, ref heap);
            }
            else _segs[s].SearchInto(qp, qfp, ref heap);
        }
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

public struct RouteNodeRuntime
{
    public int DimReordered; // reordered dim index; -1 = leaf
    public int Threshold;    // raw int16 value (divide by Scale to get float)
    public int LoChild;      // index into this base's route tree
    public int HiChild;
    public int SegIdx;       // global sub-seg index (leaves only; -1 for internal)
}
