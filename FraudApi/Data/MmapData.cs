using System.Runtime.InteropServices;
using FraudApi.FraudDetection;

namespace FraudApi.Data;

// vptree.bin layout:
//   [4B] magic 0x56505452
//   [4B] total (N)
//   [4B] nodeCount
//   [4B] bucketSize (ignored at runtime)
//   [4B] leafIdxCount
//   [14×4B] dimOrder
//   [nodeCount×16B] VpNode[]
//   [leafIdxCount×4B] leafIndices
//   [N×14×2B] vecs (row-major, variance-ordered dims)
//   [N×1B] labels
public sealed unsafe class MmapData
{
    [DllImport("libc")] private static extern int madvise(void* addr, nuint length, int advice);
    private const int MadvHugePage = 14;
    private const int Magic = 0x56505452; // "VPTR"

    public VpNode* Nodes;
    public int*    LeafIndices;
    public short*  Vecs;
    public byte*   Labels;
    public int     NodeCount;
    public int     Total;
    public int[]   DimOrder = null!;

#pragma warning disable CS0414
    private byte[] _data = null!; // pinned; GC must not collect while pointers are live
#pragma warning restore CS0414

    public VpTreeEngine CreateEngine() =>
        new(Nodes, LeafIndices, Vecs, Labels, DimOrder);

    public static MmapData Load(string path)
    {
        var fileSize = (int)new FileInfo(path).Length;
        var data = GC.AllocateUninitializedArray<byte>(fileSize, pinned: true);
        using var fs = File.OpenRead(path);
        fs.ReadExactly(data);

        fixed (byte* p = data)
        {
            madvise(p, (nuint)fileSize, MadvHugePage);
            for (long i = 0; i < fileSize; i += 4096)
                _ = p[i];
        }

        fixed (byte* ptr = &MemoryMarshal.GetArrayDataReference(data))
        {
            int magic = *(int*)(ptr + 0);
            if (magic != Magic)
                throw new InvalidDataException($"vptree.bin: expected 0x{Magic:X8}, got 0x{magic:X8}");

            int total        = *(int*)(ptr + 4);
            int nodeCount    = *(int*)(ptr + 8);
            // bucketSize     = *(int*)(ptr + 12) — not needed at runtime
            int leafIdxCount = *(int*)(ptr + 16);

            int* dimOrderPtr = (int*)(ptr + 20);
            var dimOrder = new int[14];
            new ReadOnlySpan<int>(dimOrderPtr, 14).CopyTo(dimOrder);

            // offset 20 + 14*4 = 76
            var nodes   = (VpNode*)(ptr + 76);
            var leafIdx = (int*)   (ptr + 76 + (long)nodeCount * sizeof(VpNode));
            var vecs    = (short*) ((byte*)leafIdx + (long)leafIdxCount * sizeof(int));
            var labels  = (byte*)  (vecs + (long)total * 14);

            return new MmapData
            {
                Nodes        = nodes,
                LeafIndices  = leafIdx,
                Vecs         = vecs,
                Labels       = labels,
                NodeCount    = nodeCount,
                Total        = total,
                DimOrder     = dimOrder,
                _data        = data
            };
        }
    }
}
