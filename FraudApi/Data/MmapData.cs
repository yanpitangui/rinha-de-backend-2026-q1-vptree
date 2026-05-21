using System.Runtime.InteropServices;
using FraudApi.FraudDetection;
using FraudApi.Shared;

namespace FraudApi.Data;

// vptree.bin layout (VPTS format):
//   [4B]      magic 0x56505453 "VPTS"
//   [4B]      numSegments = 16
//   [14x4B]   dimOrder (56B)
//   [16x16B]  per-seg headers: [nodeCount(4), leafBlockCount(4), totalVectors(4), reserved(4)] = 256B
//   Header total: 4+4+56+256 = 320B
//   Nodes:      seg0..15 concatenated, nodeCount[s] × 64B each
//   LeafBlocks: seg0..15 concatenated, leafBlockCount[s] × 224B each
//   LeafLabels: seg0..15 concatenated, leafBlockCount[s] × 8B each
//   FastPath:   appended, starts with magic 0x46415333
public sealed unsafe class MmapData
{
    [DllImport("libc")] private static extern int madvise(void* addr, nuint length, int advice);
    [DllImport("libc")] private static extern int mlock(void* addr, nuint length);
    private const int MadvHugePage = 14;
    private const int Magic        = 0x56505453; // "VPTS"

#pragma warning disable CS0414
    private byte[] _data = null!; // pinned VP-tree bytes; GC must not collect while pointers live
#pragma warning restore CS0414

    private SegmentedVpTreeEngine _engine = null!;
    public ProfileFastPath? FastPath;

    public SegmentedVpTreeEngine CreateEngine() => _engine;

    public static MmapData Load(string path)
    {
        long fileSize = new FileInfo(path).Length;

        using var fs = File.OpenRead(path);

        // Read header (320B) first to compute fastpathOffset before allocating pinned array.
        Span<byte> hdr = stackalloc byte[320];
        fs.ReadExactly(hdr);

        fixed (byte* hp = hdr)
        {
            int magic = *(int*)(hp + 0);
            if (magic != Magic)
                throw new InvalidDataException($"vptree.bin: expected 0x{Magic:X8}, got 0x{magic:X8}");

            int numSegs = *(int*)(hp + 4);
            if (numSegs != 16)
                throw new InvalidDataException($"vptree.bin: expected 16 segments, got {numSegs}");
        }

        // Parse per-seg headers to compute fastpathOffset.
        var nodeCounts      = new int[16];
        var leafBlockCounts = new int[16];
        fixed (byte* hp = hdr)
        {
            int* segHdrs = (int*)(hp + 64); // offset 4+4+56=64
            for (int s = 0; s < 16; s++)
            {
                nodeCounts[s]      = segHdrs[s * 4 + 0];
                leafBlockCounts[s] = segHdrs[s * 4 + 1];
            }
        }

        long curr = 320L;
        for (int s = 0; s < 16; s++) curr += (long)nodeCounts[s] * 64;
        for (int s = 0; s < 16; s++) curr += (long)leafBlockCounts[s] * sizeof(Block);
        for (int s = 0; s < 16; s++) curr += (long)leafBlockCounts[s] * 8;
        long fastpathOffset = curr;

        // Allocate pinned array for VP-tree data only (excludes fastpath section).
        int vpTreeSize = (int)fastpathOffset;
        var data = GC.AllocateUninitializedArray<byte>(vpTreeSize, pinned: true);
        hdr.CopyTo(data.AsSpan(0, 320));
        fs.ReadExactly(data.AsSpan(320, vpTreeSize - 320));

        // Read fastpath into temp buffer (parsed into managed objects, then GC'd).
        ProfileFastPath? fastPath = null;
        long fastpathSize = fileSize - fastpathOffset;
        if (fastpathSize > 0)
        {
            var fpBytes = new byte[fastpathSize];
            fs.ReadExactly(fpBytes);
            fixed (byte* fpPtr = fpBytes)
                fastPath = ProfileFastPath.LoadFromPointer(fpPtr, fastpathSize);
        }

        fixed (byte* p = data)
        {
            madvise(p, (nuint)vpTreeSize, MadvHugePage);
            for (long i = 0; i < vpTreeSize; i += 4096) _ = p[i];
            mlock(p, (nuint)vpTreeSize);
        }

        fixed (byte* ptr = &MemoryMarshal.GetArrayDataReference(data))
        {
            var dimOrder = new int[14];
            new ReadOnlySpan<int>((int*)(ptr + 8), 14).CopyTo(dimOrder);

            curr = 320L;
            var nodeOffsets = new long[16];
            for (int s = 0; s < 16; s++) { nodeOffsets[s] = curr; curr += (long)nodeCounts[s] * 64; }

            var leafBlockOffsets = new long[16];
            for (int s = 0; s < 16; s++) { leafBlockOffsets[s] = curr; curr += (long)leafBlockCounts[s] * sizeof(Block); }

            var leafLabelOffsets = new long[16];
            for (int s = 0; s < 16; s++) { leafLabelOffsets[s] = curr; curr += (long)leafBlockCounts[s] * 8; }

            var segs = new VpTreeEngine[16];
            for (int s = 0; s < 16; s++)
                segs[s] = new VpTreeEngine(
                    (VpNode*)(ptr + nodeOffsets[s]),
                    (Block*) (ptr + leafBlockOffsets[s]),
                    (byte*)  (ptr + leafLabelOffsets[s]),
                    dimOrder);

            return new MmapData
            {
                _engine  = new SegmentedVpTreeEngine(segs, dimOrder),
                FastPath = fastPath,
                _data    = data
            };
        }
    }
}
