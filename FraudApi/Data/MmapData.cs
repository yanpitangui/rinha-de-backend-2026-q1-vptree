using System.Runtime.InteropServices;
using FraudApi.FraudDetection;
using FraudApi.Shared;

namespace FraudApi.Data;

// vptree.bin layout:
//   [4B] magic 0x56505454 "VPTT"
//   [4B] N  [4B] nodeCount  [4B] bucketSize  [4B] leafBlockCount
//   [14×4B] dimOrder
//   nodes:      nodeCount × 64B (VpNode, inline VP vector)
//   leafBlocks: leafBlockCount × 224B (Block, column-major 8-wide)
//   leafLabels: leafBlockCount × 8B
public sealed unsafe class MmapData
{
    [DllImport("libc")] private static extern int madvise(void* addr, nuint length, int advice);
    private const int MadvHugePage = 14;
    private const int Magic        = 0x56505454; // "VPTT"

    public VpNode* Nodes;
    public Block*  LeafBlocks;
    public byte*   LeafLabels;
    public int     NodeCount;
    public int     Total;
    public int     LeafBlockCount;
    public int[]   DimOrder = null!;

#pragma warning disable CS0414
    private byte[] _data = null!; // pinned; GC must not collect while pointers are live
#pragma warning restore CS0414

    public VpTreeEngine CreateEngine() =>
        new(Nodes, LeafBlocks, LeafLabels, DimOrder);

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

            int total          = *(int*)(ptr + 4);
            int nodeCount      = *(int*)(ptr + 8);
            // bucketSize      = *(int*)(ptr + 12); // not needed at runtime
            int leafBlockCount = *(int*)(ptr + 16);

            // dimOrder: 14 ints at offset 20
            int* dimOrderPtr = (int*)(ptr + 20);
            var dimOrder = new int[14];
            new ReadOnlySpan<int>(dimOrderPtr, 14).CopyTo(dimOrder);

            // nodes at offset 20 + 14*4 = 76; each node = 64 bytes
            var nodes = (VpNode*)(ptr + 76);

            // leafBlocks after nodes
            var leafBlocks = (Block*)((byte*)nodes + (long)nodeCount * sizeof(VpNode));

            // leafLabels after leafBlocks
            var leafLabels = (byte*)((byte*)leafBlocks + (long)leafBlockCount * sizeof(Block));

            return new MmapData
            {
                Nodes          = nodes,
                LeafBlocks     = leafBlocks,
                LeafLabels     = leafLabels,
                NodeCount      = nodeCount,
                Total          = total,
                LeafBlockCount = leafBlockCount,
                DimOrder       = dimOrder,
                _data          = data
            };
        }
    }
}
