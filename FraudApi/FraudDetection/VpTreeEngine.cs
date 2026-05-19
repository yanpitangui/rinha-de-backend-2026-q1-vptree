using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace FraudApi.FraudDetection;

[StructLayout(LayoutKind.Sequential, Size = 16)]
public struct VpNode
{
    public int VpIdxOrCount;  // internal: vantage point global idx; leaf: vector count
    public float Threshold;   // internal: partition distance mu (normalized linear, [0,√14])
    public int Left;          // internal: left child node idx; leaf: start in leaf index array
    public int Right;         // internal: right child node idx; leaf: -1
}

public sealed unsafe class VpTreeEngine
{
    private const float InvScale = 1.0f / Vectorizer.Scale;

    private readonly VpNode* _nodes;
    private readonly int* _leafIdx;
    private readonly short* _vecs;   // N×14 row-major, dims in dimOrder sequence
    private readonly byte* _labels;
    private readonly int[] _dimOrder;

    public VpTreeEngine(VpNode* nodes, int* leafIdx, short* vecs, byte* labels, int[] dimOrder)
    {
        _nodes   = nodes;
        _leafIdx = leafIdx;
        _vecs    = vecs;
        _labels  = labels;
        _dimOrder = dimOrder;
    }

    [SkipLocalsInit]
    public int Search(Span<short> query)
    {
        Span<short> q = stackalloc short[14];
        for (int di = 0; di < 14; di++) q[di] = query[_dimOrder[di]];

        var heap = new KnnHeap5();
        fixed (short* qp = q)
            SearchNode(0, qp, ref heap);
        return heap.FraudCount;
    }

    private void SearchNode(int nodeIdx, short* q, ref KnnHeap5 heap)
    {
        VpNode* node = _nodes + nodeIdx;

        if (node->Right == -1)
        {
            int start = node->Left;
            int count = node->VpIdxOrCount;
            for (int i = 0; i < count; i++)
            {
                int idx = _leafIdx[start + i];
                heap.TryAdd(DistNorm(q, _vecs + (long)idx * 14), _labels[idx]);
            }
            return;
        }

        int vpIdx    = node->VpIdxOrCount;
        float vpDist = DistNorm(q, _vecs + (long)vpIdx * 14);
        heap.TryAdd(vpDist, _labels[vpIdx]);

        float mu  = node->Threshold;
        float tau = heap.Worst;

        if (vpDist <= mu)
        {
            SearchNode(node->Left, q, ref heap);
            tau = heap.Worst;
            if (mu - vpDist <= tau)
                SearchNode(node->Right, q, ref heap);
        }
        else
        {
            SearchNode(node->Right, q, ref heap);
            tau = heap.Worst;
            if (vpDist - mu <= tau)
                SearchNode(node->Left, q, ref heap);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float DistNorm(short* q, short* v)
    {
        long acc = 0;
        for (int d = 0; d < 14; d++)
        {
            int diff = q[d] - v[d];
            acc += diff * diff;
        }
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
            _d[_count] = d;
            _l[_count] = lbl;
            if (++_count == 5) BuildHeap();
            return;
        }
        if (d >= _d[0]) return;
        _d[0] = d; _l[0] = lbl;
        SiftDown(0);
    }

    private void BuildHeap()
    {
        SiftDown(1);
        SiftDown(0);
    }

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

    public int FraudCount
    {
        get { int c = 0; for (int i = 0; i < 5; i++) c += _l[i]; return c; }
    }
}
