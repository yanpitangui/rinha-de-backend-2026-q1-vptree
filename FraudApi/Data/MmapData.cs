using System.Runtime.InteropServices;
using FraudApi.FraudDetection;
using FraudApi.Shared;

namespace FraudApi.Data;

// vptree.bin layout (VPTS format):
//   numSegments=16: header = 320B (legacy)
//   numSegments=17: header = 344B (Seg 10 split into lo[10] + hi[16])
//   [4B]      magic 0x56505453 "VPTS"
//   [4B]      numSegments = 16 or 17
//   [14x4B]   dimOrder (56B)
//   [N×16B]   per-seg headers: [nodeCount(4), leafBlockCount(4), totalVectors(4), reserved(4)]
//   [8B]      (numSegments=17 only) seg10SplitDim(4) + seg10SplitThreshold(4)
//   Nodes:      seg0..N-1 concatenated, nodeCount[s] × 64B each
//   LeafBlocks: seg0..N-1 concatenated, leafBlockCount[s] × 448B each
//   LeafLabels: seg0..N-1 concatenated, leafBlockCount[s] × 16B each
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

        // Read first 8B (magic + numSegments) to determine header size.
        Span<byte> hdr = stackalloc byte[344]; // max header size (17-seg = 344B)
        fs.ReadExactly(hdr[..8]);

        int numSegs;
        fixed (byte* hp = hdr)
        {
            int magic = *(int*)(hp + 0);
            if (magic != Magic)
                throw new InvalidDataException($"vptree.bin: expected 0x{Magic:X8}, got 0x{magic:X8}");
            numSegs = *(int*)(hp + 4);
            if (numSegs != 16 && numSegs != 17)
                throw new InvalidDataException($"vptree.bin: expected 16 or 17 segments, got {numSegs}");
        }
        int hdrSize = numSegs == 16 ? 320 : 344; // 4+4+56+N*16[+8]
        fs.ReadExactly(hdr[8..hdrSize]);

        // Parse per-seg headers to compute fastpathOffset.
        var nodeCounts      = new int[numSegs];
        var leafBlockCounts = new int[numSegs];
        int splitDim        = -1;
        short splitThresh   = 0;
        fixed (byte* hp = hdr)
        {
            int* segHdrs = (int*)(hp + 64); // offset 4+4+56=64
            for (int s = 0; s < numSegs; s++)
            {
                nodeCounts[s]      = segHdrs[s * 4 + 0];
                leafBlockCounts[s] = segHdrs[s * 4 + 1];
            }
            if (numSegs == 17)
            {
                int* ext = (int*)(hp + 64 + 17 * 16); // offset 64+272=336
                splitDim    = ext[0];
                splitThresh = (short)ext[1];
            }
        }

        long curr = hdrSize;
        for (int s = 0; s < numSegs; s++) curr += (long)nodeCounts[s] * 64;
        for (int s = 0; s < numSegs; s++) curr += (long)leafBlockCounts[s] * sizeof(Block);
        for (int s = 0; s < numSegs; s++) curr += (long)leafBlockCounts[s] * 16;
        long fastpathOffset = curr;

        // Allocate pinned array for VP-tree data only (excludes fastpath section).
        int vpTreeSize = (int)fastpathOffset;
        var data = GC.AllocateUninitializedArray<byte>(vpTreeSize, pinned: true);
        hdr[..hdrSize].CopyTo(data.AsSpan(0, hdrSize));
        fs.ReadExactly(data.AsSpan(hdrSize, vpTreeSize - hdrSize));

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

            curr = hdrSize;
            var nodeOffsets = new long[numSegs];
            for (int s = 0; s < numSegs; s++) { nodeOffsets[s] = curr; curr += (long)nodeCounts[s] * 64; }

            var leafBlockOffsets = new long[numSegs];
            for (int s = 0; s < numSegs; s++) { leafBlockOffsets[s] = curr; curr += (long)leafBlockCounts[s] * sizeof(Block); }

            var leafLabelOffsets = new long[numSegs];
            for (int s = 0; s < numSegs; s++) { leafLabelOffsets[s] = curr; curr += (long)leafBlockCounts[s] * 16; }

            var segs = new VpTreeEngine[numSegs];
            for (int s = 0; s < numSegs; s++)
                segs[s] = new VpTreeEngine(
                    (VpNode*)(ptr + nodeOffsets[s]),
                    (Block*) (ptr + leafBlockOffsets[s]),
                    (byte*)  (ptr + leafLabelOffsets[s]),
                    dimOrder);

            return new MmapData
            {
                _engine  = new SegmentedVpTreeEngine(segs, dimOrder, splitDim, splitThresh),
                FastPath = fastPath,
                _data    = data
            };
        }
    }
}
