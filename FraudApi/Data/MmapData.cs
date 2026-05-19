using System.Runtime.InteropServices;
using FraudApi.FraudDetection;
using FraudApi.Shared;

namespace FraudApi.Data;

// vptree.bin layout:
//   [4B] magic 0x56505453 "VPTS"
//   [4B] N  [4B] nodeCount  [4B] bucketSize  [4B] internalCount  [4B] leafBlockCount
//   [14×4B] dimOrder
//   nodes:      nodeCount × 16B (VpNode)
//   vpVecs:     internalCount × 14 × 2B  (row-major, variance-ordered)
//   vpLabels:   internalCount × 1B
//   leafBlocks: leafBlockCount × sizeof(Block)  (224B each, column-major 8-wide)
//   leafLabels: leafBlockCount × 8B
public sealed unsafe class MmapData
{
    [DllImport("libc")] private static extern int madvise(void* addr, nuint length, int advice);
    private const int MadvHugePage = 14;
    private const int Magic        = 0x56505453; // "VPTS"

    public VpNode* Nodes;
    public short*  VpVecs;      // internalCount × 14 shorts, row-major, variance-ordered
    public byte*   VpLabels;    // internalCount bytes
    public Block*  LeafBlocks;  // leafBlockCount × Block (column-major, 8 vecs per block)
    public byte*   LeafLabels;  // leafBlockCount × 8 bytes
    public int     NodeCount;
    public int     Total;
    public int     InternalCount;
    public int     LeafBlockCount;
    public int[]   DimOrder = null!;

#pragma warning disable CS0414
    private byte[] _data = null!; // pinned; GC must not collect while pointers are live
#pragma warning restore CS0414

    public VpTreeEngine CreateEngine() =>
        new(Nodes, VpVecs, VpLabels, LeafBlocks, LeafLabels, DimOrder);

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
            int internalCount  = *(int*)(ptr + 16);
            int leafBlockCount = *(int*)(ptr + 20);

            // dimOrder: 14 ints at offset 24
            int* dimOrderPtr = (int*)(ptr + 24);
            var dimOrder = new int[14];
            new ReadOnlySpan<int>(dimOrderPtr, 14).CopyTo(dimOrder);

            // nodes at offset 24 + 14*4 = 80
            var nodes = (VpNode*)(ptr + 80);

            // vpVecs after nodes
            var vpVecs = (short*)((byte*)nodes + (long)nodeCount * sizeof(VpNode));

            // vpLabels after vpVecs
            var vpLabels = (byte*)(vpVecs + (long)internalCount * 14);

            // leafBlocks after vpLabels (sizeof(Block) = 14*8*2 = 224)
            var leafBlocks = (Block*)(vpLabels + internalCount);

            // leafLabels after leafBlocks
            var leafLabels = (byte*)((byte*)leafBlocks + (long)leafBlockCount * sizeof(Block));

            return new MmapData
            {
                Nodes          = nodes,
                VpVecs         = vpVecs,
                VpLabels       = vpLabels,
                LeafBlocks     = leafBlocks,
                LeafLabels     = leafLabels,
                NodeCount      = nodeCount,
                Total          = total,
                InternalCount  = internalCount,
                LeafBlockCount = leafBlockCount,
                DimOrder       = dimOrder,
                _data          = data
            };
        }
    }
}
