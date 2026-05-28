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

        var heap = new KnnHeap5();
        fixed (short* qp = q)
            SearchInto(qp, ref heap);
        return heap.FraudCount;
    }

    // Called by SegmentedVpTreeEngine with pre-reordered query pointer and shared heap.
    // All distances in raw int16 squared units (long). VP triangle bound uses linear sqrt.
    [SkipLocalsInit]
    internal void SearchInto(short* qp, ref KnnHeap5 heap)
    {
        StackEntry* stack = stackalloc StackEntry[64];
        int top = 0;
        int curNode = 0;
        long curMin = 0;

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
                ScanLeafBlocks(qp, node->Left, node->VpIdxOrCount, ref heap);
                if (top == 0) break;
                StackEntry le = stack[--top];
                curNode = le.NodeIdx; curMin = le.MinDistSq;
                continue;
            }

            long vpDistSq = DistSqVp(qp, node->Vp);
            heap.TryAddSq(vpDistSq, node->VpLabel);

            double vpDist = Math.Sqrt(vpDistSq);
            double mu     = node->Threshold; // raw linear int distance
            int near, far;
            double gap;
            if (vpDist <= mu) { near = node->Left;  far = node->Right; gap = mu - vpDist; }
            else              { near = node->Right; far = node->Left;  gap = vpDist - mu; }

            Sse.Prefetch0(_nodes + near);

            long farMinDist = (long)(gap * gap);
            if (farMinDist <= heap.Worst)
                stack[top++] = new StackEntry(far, farMinDist);

            curNode = near;
            curMin = 0;
        }
    }

    [SkipLocalsInit]
    private void ScanLeafBlocks(short* qp, int blockStart, int blockCount, ref KnnHeap5 heap)
    {
        long* dptr    = stackalloc long[16];
        long  boundSq = heap.Worst;

        int prefetchLimit = Math.Min(blockCount, 8);
        for (int p = 0; p < prefetchLimit; p++)
            Sse.Prefetch0(_leafBlocks + blockStart + p);

        for (int bi = 0; bi < blockCount; bi++)
        {
            if (bi + 7 < blockCount)
                Sse.Prefetch0(_leafBlocks + blockStart + bi + 7);

            Block* block = _leafBlocks + blockStart + bi;
            if (!ProcessBlock(block, qp, dptr, boundSq)) continue;

            byte* labels = _leafLabels + ((long)(blockStart + bi) << 4);
            for (int i = 0; i < 16; i++)
            {
                long dsq = dptr[i];
                if (dsq >= boundSq) continue;
                heap.TryAddSq(dsq, labels[i]);
                boundSq = heap.Worst;
            }
        }
    }

    // Per-lane squared int16 distance over 16 lanes, accumulated in int64 (exact).
    // Returns false if all 16 lanes already exceed boundSq (block fully prunable).
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [SkipLocalsInit]
    private static bool ProcessBlock(Block* block, short* qp, long* dptr, long boundSq)
    {
        short* blockBase = (short*)block;

        if (Avx2.IsSupported)
        {
            var acc0 = Vector256<long>.Zero; // lanes 0-3
            var acc1 = Vector256<long>.Zero; // lanes 4-7
            var acc2 = Vector256<long>.Zero; // lanes 8-11
            var acc3 = Vector256<long>.Zero; // lanes 12-15
            var bound = Vector256.Create(boundSq);

            for (int di = 0; di < 14; di++)
            {
                var qv   = Vector256.Create(qp[di]);
                var v    = Vector256.Load(blockBase + di * 16);
                var diff = Avx2.Subtract(v, qv);                          // 16 int16
                var dlo  = Avx2.ConvertToVector256Int32(diff.GetLower()); // 8 int32 (lanes 0-7)
                var dhi  = Avx2.ConvertToVector256Int32(diff.GetUpper()); // 8 int32 (lanes 8-15)
                var sqlo = Avx2.MultiplyLow(dlo, dlo);                    // diff^2, < 4e8, fits int32
                var sqhi = Avx2.MultiplyLow(dhi, dhi);
                acc0 = Avx2.Add(acc0, Avx2.ConvertToVector256Int64(sqlo.GetLower()));
                acc1 = Avx2.Add(acc1, Avx2.ConvertToVector256Int64(sqlo.GetUpper()));
                acc2 = Avx2.Add(acc2, Avx2.ConvertToVector256Int64(sqhi.GetLower()));
                acc3 = Avx2.Add(acc3, Avx2.ConvertToVector256Int64(sqhi.GetUpper()));

                // Every 2 dims: partial sum is a valid lower bound -- reject block if no lane below bound.
                if ((di & 1) == 1 && di < 13)
                {
                    var m0 = Avx2.CompareGreaterThan(bound, acc0); // lanes where acc < bound
                    var m1 = Avx2.CompareGreaterThan(bound, acc1);
                    var m2 = Avx2.CompareGreaterThan(bound, acc2);
                    var m3 = Avx2.CompareGreaterThan(bound, acc3);
                    var any = Avx2.Or(Avx2.Or(m0, m1), Avx2.Or(m2, m3));
                    if (Avx2.MoveMask(any.AsByte()) == 0) return false;
                }
            }

            Vector256.Store(acc0, dptr);
            Vector256.Store(acc1, dptr + 4);
            Vector256.Store(acc2, dptr + 8);
            Vector256.Store(acc3, dptr + 12);
            return true;
        }

        for (int i = 0; i < 16; i++) dptr[i] = 0;
        for (int di = 0; di < 14; di++)
        {
            long   qd = qp[di];
            short* dd = blockBase + di * 16;
            for (int i = 0; i < 16; i++) { long d = dd[i] - qd; dptr[i] += d * d; }
        }
        return true;
    }

    // Raw int16 squared distance (no normalization, no sqrt) over 16 lanes.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static long DistSqVp(short* q, short* v)
    {
        var d    = Avx2.Subtract(Vector256.Load(q), Vector256.Load(v)); // 16 int16
        var dlo  = Avx2.ConvertToVector256Int32(d.GetLower());          // 8 int32
        var dhi  = Avx2.ConvertToVector256Int32(d.GetUpper());
        var sqlo = Avx2.MultiplyLow(dlo, dlo);
        var sqhi = Avx2.MultiplyLow(dhi, dhi);
        var a    = Avx2.ConvertToVector256Int64(sqlo.GetLower());
        var b    = Avx2.ConvertToVector256Int64(sqlo.GetUpper());
        var c    = Avx2.ConvertToVector256Int64(sqhi.GetLower());
        var e    = Avx2.ConvertToVector256Int64(sqhi.GetUpper());
        var s    = Avx2.Add(Avx2.Add(a, b), Avx2.Add(c, e));            // 4 int64
        var s2   = Sse2.Add(s.GetLower(), s.GetUpper());
        return s2.GetElement(0) + s2.GetElement(1);
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
    // BB mode (VPTB): bounding boxes [256*16] in reordered dim space.
    private readonly short[]? _bbMins;
    private readonly short[]? _bbMaxs;
    // Per-base route node boxes [256][nodeCount*32] (stride 32: 16 min + 16 max), reordered space.
    private readonly short[][]? _routeBoxes;
    private readonly short _dim8Thresh, _dim2Thresh, _dim0Q1, _dim0Q2, _dim0Q3;

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

    // VPTB constructor: 256-partition BB-pruned KD-routing with per-node boxes.
    public SegmentedVpTreeEngine(
        VpTreeEngine[] segs, int[] dimOrder,
        RouteNodeRuntime[][] routeTrees256,
        short[][] routeBoxes256,
        short[] bbMins, short[] bbMaxs,
        short dim8Thresh, short dim2Thresh,
        short dim0Q1, short dim0Q2, short dim0Q3)
    {
        _segs              = segs;
        _dimOrder          = dimOrder;
        _routeTrees        = routeTrees256;
        _routeBoxes        = routeBoxes256;
        _bbMins            = bbMins;
        _bbMaxs            = bbMaxs;
        _dim8Thresh        = dim8Thresh;
        _dim2Thresh        = dim2Thresh;
        _dim0Q1            = dim0Q1;
        _dim0Q2            = dim0Q2;
        _dim0Q3            = dim0Q3;
        _sortedNeighbors   = Array.Empty<byte>();
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
        bool hasLastTx    = query[5] > -5000;
        bool isOnline     = query[9] > 5000;
        bool cardPresent  = query[10] > 5000;
        bool unknownMerch = query[11] > 5000;
        int segKey = (hasLastTx ? 8 : 0) | (isOnline ? 4 : 0) | (cardPresent ? 2 : 0) | (unknownMerch ? 1 : 0);

        // Extend to 8-bit key for BB mode.
        int segKey8 = segKey;
        if (_bbMins != null)
        {
            int txCountBit  = query[8] > _dim8Thresh ? 1 : 0;
            int amtVsAvgBit = query[2] > _dim2Thresh ? 1 : 0;
            int amtBucket   = GetDim0Bucket(query[0]);
            segKey8 = segKey | (txCountBit << 4) | (amtVsAvgBit << 5) | (amtBucket << 6);
        }

        Span<short> q = stackalloc short[16];
        for (int di = 0; di < 14; di++) q[di] = query[_dimOrder[di]];
        q[14] = 0; q[15] = 0;

        var heap = new KnnHeap5();
        fixed (short* qp = q)
        {
            if (_bbMins != null)
                SearchBB(segKey8, qp, ref heap);
            else if (_routeTrees != null)
                SearchKD(segKey, qp, ref heap);
            else if (_splits32 != null)
                Search32(segKey, qp, ref heap);
            else
                SearchLegacy(segKey, qp, ref heap);
        }
        return heap.FraudCount;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int GetDim0Bucket(short v)
    {
        if (v <= _dim0Q1) return 0;
        if (v <= _dim0Q2) return 1;
        if (v <= _dim0Q3) return 2;
        return 3;
    }

    private void SearchKD(int segKey, short* qp, ref KnnHeap5 heap)
    {
        SearchBaseKD(segKey, qp, ref heap);
        int sortBase = segKey * 15;
        for (int i = 0; i < 15; i++)
        {
            int b = _sortedNeighbors[sortBase + i];
            if (s_crossDist16[segKey * 16 + b] >= heap.Worst) break;
            SearchBaseKD(b, qp, ref heap);
        }
    }

    [SkipLocalsInit]
    private void SearchBB(int primaryKey, short* qp, ref KnnHeap5 heap)
    {
        // Search primary partition first to seed a tight bound.
        SearchBaseKD(primaryKey, qp, ref heap);

        // Lower bound per partition (raw int16 squared) via its root bounding box.
        Span<long> bounds = stackalloc long[256];
        fixed (short* mins = _bbMins)
        fixed (short* maxs = _bbMaxs)
        {
            for (int b = 0; b < 256; b++)
            {
                if (b == primaryKey) { bounds[b] = 0; continue; }
                bounds[b] = LowerBoundBoxAvx2(qp, mins + b * 16, maxs + b * 16);
            }
        }

        // Insertion sort 256 indices by bound ascending.
        Span<byte> order = stackalloc byte[256];
        for (int i = 0; i < 256; i++) order[i] = (byte)i;
        for (int i = 1; i < 256; i++)
        {
            byte key      = order[i];
            long keyBound = bounds[key];
            int  j        = i - 1;
            while (j >= 0 && bounds[order[j]] > keyBound)
            {
                order[j + 1] = order[j];
                j--;
            }
            order[j + 1] = key;
        }

        // Visit in order; heap.Worst and box bounds share raw int16 squared units (no conversion).
        for (int i = 0; i < 256; i++)
        {
            byte idx = order[i];
            if (bounds[idx] > heap.Worst) break;
            if (idx == (byte)primaryKey) continue;
            SearchBaseKD(idx, qp, ref heap);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long LowerBoundBoxAvx2(short* q, short* min, short* max)
    {
        var vq    = Vector256.Load(q);
        var vmin  = Vector256.Load(min);
        var vmax  = Vector256.Load(max);
        var zero  = Vector256<short>.Zero;
        var below = Avx2.Max(Avx2.Subtract(vmin, vq), zero); // max(min-q, 0)
        var above = Avx2.Max(Avx2.Subtract(vq, vmax), zero); // max(q-max, 0)
        var diff  = Avx2.Max(below, above);
        var sq    = Avx2.MultiplyAddAdjacent(diff, diff);     // 8×int32 pair-sums
        var lo64  = Avx2.ConvertToVector256Int64(sq.GetLower());
        var hi64  = Avx2.ConvertToVector256Int64(sq.GetUpper());
        var s64   = Avx2.Add(lo64, hi64);
        var s2    = Sse2.Add(s64.GetLower(), s64.GetUpper());
        return s2.GetElement(0) + s2.GetElement(1);
    }

    // Box branch-and-bound over a base's route tree. Each node carries its subtree's
    // bounding box; the box lower bound (all 14 dims) gates descent -- far tighter than
    // a single-axis split gap, so small leaf sub-segs stay cheap to prune.
    [SkipLocalsInit]
    private void SearchBaseKD(int baseIdx, short* qp, ref KnnHeap5 heap)
    {
        var tree = _routeTrees![baseIdx];
        if (tree.Length == 0) return;
        fixed (RouteNodeRuntime* nodes = tree)
        fixed (short* box = _routeBoxes![baseIdx])
        {
            StackEntry* stack = stackalloc StackEntry[128];
            int top = 0, cur = 0; long curMin = 0;
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
                    if (node->SegIdx >= 0)
                        _segs[node->SegIdx].SearchInto(qp, ref heap);
                    if (top == 0) break;
                    StackEntry e = stack[--top]; cur = e.NodeIdx; curMin = e.MinDistSq;
                    continue;
                }

                int lo = node->LoChild, hi = node->HiChild;
                long lb = LowerBoundBoxAvx2(qp, box + lo * 32, box + lo * 32 + 16);
                long rb = LowerBoundBoxAvx2(qp, box + hi * 32, box + hi * 32 + 16);

                int near, far; long nearB, farB;
                if (lb <= rb) { near = lo; nearB = lb; far = hi; farB = rb; }
                else          { near = hi; nearB = rb; far = lo; farB = lb; }

                if (farB <= heap.Worst && top < 128)
                    stack[top++] = new StackEntry(far, farB);

                if (nearB <= heap.Worst) { cur = near; curMin = nearB; continue; }

                if (top == 0) break;
                StackEntry pe = stack[--top]; cur = pe.NodeIdx; curMin = pe.MinDistSq;
            }
        }
    }

    private void Search32(int segKey, short* qp, ref KnnHeap5 heap)
    {
        var split  = _splits32![segKey];
        int ownSeg = (split.DimReordered >= 0 && qp[split.DimReordered] > split.Threshold)
            ? 16 + segKey : segKey;
        _segs[ownSeg].SearchInto(qp, ref heap);

        if (split.DimReordered >= 0)
        {
            int  otherHalf = ownSeg < 16 ? ownSeg + 16 : ownSeg - 16;
            long gap       = Math.Abs(qp[split.DimReordered] - split.Threshold);
            if (heap.Worst > gap * gap)
                _segs[otherHalf].SearchInto(qp, ref heap);
        }

        int sortBase = ownSeg * 30;
        for (int i = 0; i < 30; i++)
        {
            int s = _sortedNeighbors[sortBase + i];
            if (s_crossDist32[ownSeg * 32 + s] >= heap.Worst) break;
            _segs[s].SearchInto(qp, ref heap);
        }
    }

    private void SearchLegacy(int segKey, short* qp, ref KnnHeap5 heap)
    {
        bool isSeg10 = segKey == 10 && _splitDimReordered >= 0;
        int  ownSeg  = segKey;
        if (isSeg10)
            ownSeg = qp[_splitDimReordered] > _splitThreshold ? 16 : 10;

        _segs[ownSeg].SearchInto(qp, ref heap);

        if (isSeg10)
        {
            int  otherSeg = ownSeg == 10 ? 16 : 10;
            long gap      = Math.Abs(qp[_splitDimReordered] - _splitThreshold);
            if (heap.Worst > gap * gap)
                _segs[otherSeg].SearchInto(qp, ref heap);
        }

        int sortBase = segKey * 15;
        for (int i = 0; i < 15; i++)
        {
            int s = _sortedNeighbors[sortBase + i];
            if (heap.Worst <= s_crossDist16[segKey * 16 + s]) break;
            if (s == 10 && _splitDimReordered >= 0)
            {
                _segs[10].SearchInto(qp, ref heap);
                _segs[16].SearchInto(qp, ref heap);
            }
            else _segs[s].SearchInto(qp, ref heap);
        }
    }
}

public unsafe struct KnnHeap5
{
    private fixed long _d[5]; // raw int16 squared distances
    private fixed byte _l[5];
    private int _count;

    // Returns max dist^2 in heap (long.MaxValue when not full).
    public long Worst => _count < 5 ? long.MaxValue : _d[0];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void TryAddSq(long dsq, byte lbl)
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
            long td = _d[i]; _d[i] = _d[lg]; _d[lg] = td;
            byte tl = _l[i]; _l[i] = _l[lg]; _l[lg] = tl;
            i = lg;
        }
    }

    public int FraudCount { get { int c = 0; for (int i = 0; i < 5; i++) c += _l[i]; return c; } }
}

internal readonly struct StackEntry
{
    public readonly int  NodeIdx;
    public readonly long MinDistSq;
    public StackEntry(int nodeIdx, long minDistSq) { NodeIdx = nodeIdx; MinDistSq = minDistSq; }
}

public struct RouteNodeRuntime
{
    public int DimReordered; // reordered dim index; -1 = leaf
    public int Threshold;    // raw int16 value (divide by Scale to get float)
    public int LoChild;      // index into this base's route tree
    public int HiChild;
    public int SegIdx;       // global sub-seg index (leaves only; -1 for internal)
}
