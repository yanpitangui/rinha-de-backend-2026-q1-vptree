using System.Runtime.InteropServices;
using FraudApi.FraudDetection;
using FraudApi.Shared;

namespace FraudApi.Data;

// vptree.bin layout (VPTS format):
//   numSegments=16: header = 320B (legacy)
//   numSegments=17: header = 344B (Seg 10 split into lo[10] + hi[16])
//   numSegments=32: header = 704B (all 16 base segs split: lo=s, hi=16+s; 16 split specs)
//   [4B]      magic 0x56505453 "VPTS"
//   [4B]      numSegments = 16, 17, or 32
//   [14x4B]   dimOrder (56B)
//   [N×16B]   per-seg headers: [nodeCount(4), leafBlockCount(4), totalVectors(4), reserved(4)]
//   [8B]      (numSegments=17 only) seg10SplitDim(4) + seg10SplitThreshold(4)
//   [128B]    (numSegments=32 only) 16×[splitDim(4)+splitThresh(4)] for base segs 0..15
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
    private const int MagicKD      = 0x56505454; // "VPTT" — KD-routing format
    private const int MagicBB      = 0x56505443; // "VPTC" — KD-routing + partition boxes + per-leaf-block boxes

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

        // Peek magic to dispatch format.
        Span<byte> magic4 = stackalloc byte[4];
        fs.ReadExactly(magic4);
        int peekMagic;
        fixed (byte* mp = magic4) peekMagic = *(int*)mp;
        if (peekMagic == MagicKD)
            return LoadKD(path, fileSize);
        if (peekMagic == MagicBB)
            return LoadBB(path, fileSize);
        fs.Seek(0, SeekOrigin.Begin);

        // Read first 8B (magic + numSegments) to determine header size.
        Span<byte> hdr = stackalloc byte[704]; // max header size (32-seg = 704B)
        fs.ReadExactly(hdr[..8]);

        int numSegs;
        fixed (byte* hp = hdr)
        {
            int magic = *(int*)(hp + 0);
            if (magic != Magic)
                throw new InvalidDataException($"vptree.bin: expected 0x{Magic:X8}, got 0x{magic:X8}");
            numSegs = *(int*)(hp + 4);
            if (numSegs != 16 && numSegs != 17 && numSegs != 32)
                throw new InvalidDataException($"vptree.bin: expected 16, 17, or 32 segments, got {numSegs}");
        }
        int hdrSize = numSegs == 16 ? 320 : numSegs == 17 ? 344 : 704;
        fs.ReadExactly(hdr[8..hdrSize]);

        // Parse per-seg headers + split specs.
        var nodeCounts      = new int[numSegs];
        var leafBlockCounts = new int[numSegs];
        // Legacy 17-seg fields
        int   legacySplitDim    = -1;
        short legacySplitThresh = 0;
        // New 32-seg fields
        int[]?   splitDims32    = null;
        short[]? splitThreshs32 = null;
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
                legacySplitDim    = ext[0];
                legacySplitThresh = (short)ext[1];
            }
            if (numSegs == 32)
            {
                // Split specs start at offset 64 + 32*16 = 64+512 = 576
                int* specs = (int*)(hp + 576);
                splitDims32    = new int[16];
                splitThreshs32 = new short[16];
                for (int s = 0; s < 16; s++)
                {
                    splitDims32[s]    = specs[s * 2];
                    splitThreshs32[s] = (short)specs[s * 2 + 1];
                }
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

            SegmentedVpTreeEngine engine = numSegs == 32
                ? new SegmentedVpTreeEngine(segs, dimOrder, splitDims32!, splitThreshs32!)
                : new SegmentedVpTreeEngine(segs, dimOrder, legacySplitDim, legacySplitThresh);

            return new MmapData
            {
                _engine  = engine,
                FastPath = fastPath,
                _data    = data
            };
        }
    }

    private static MmapData LoadKD(string path, long fileSize)
    {
        using var fs = File.OpenRead(path);

        int numSubSegs;
        int[] dimOrder;
        int[] nodeCounts, leafBlockCounts;
        RouteNodeRuntime[][] routeTrees;

        {
            using var br = new System.IO.BinaryReader(fs, System.Text.Encoding.UTF8, leaveOpen: true);
            if (br.ReadInt32() != MagicKD) throw new InvalidDataException("VPTT magic mismatch");
            numSubSegs = br.ReadInt32();
            dimOrder   = new int[14];
            for (int i = 0; i < 14; i++) dimOrder[i] = br.ReadInt32();

            nodeCounts      = new int[numSubSegs];
            leafBlockCounts = new int[numSubSegs];
            for (int s = 0; s < numSubSegs; s++)
            {
                nodeCounts[s]      = br.ReadInt32();
                leafBlockCounts[s] = br.ReadInt32();
                br.ReadInt32(); // totalVectors
                br.ReadInt32(); // reserved
            }

            var routeNodeCounts = new int[16];
            for (int b = 0; b < 16; b++) routeNodeCounts[b] = br.ReadInt32();

            routeTrees = new RouteNodeRuntime[16][];
            for (int b = 0; b < 16; b++)
            {
                routeTrees[b] = new RouteNodeRuntime[routeNodeCounts[b]];
                for (int n = 0; n < routeNodeCounts[b]; n++)
                    routeTrees[b][n] = new RouteNodeRuntime
                    {
                        DimReordered = br.ReadInt32(),
                        Threshold    = br.ReadInt32(),
                        LoChild      = br.ReadInt32(),
                        HiChild      = br.ReadInt32(),
                        SegIdx       = br.ReadInt32()
                    };
            }
        } // br disposed; fs still open at start of VP data

        long vpDataOffset = fs.Position;
        long vpDataSize   = 0;
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)nodeCounts[s] * 64;
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)leafBlockCounts[s] * sizeof(Block);
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)leafBlockCounts[s] * 16;

        var data = GC.AllocateUninitializedArray<byte>((int)vpDataSize, pinned: true);
        fs.ReadExactly(data);

        ProfileFastPath? fastPath = null;
        long fastpathSize = fileSize - vpDataOffset - vpDataSize;
        if (fastpathSize > 0)
        {
            var fpBytes = new byte[fastpathSize];
            fs.ReadExactly(fpBytes);
            fixed (byte* fpPtr = fpBytes)
                fastPath = ProfileFastPath.LoadFromPointer(fpPtr, fastpathSize);
        }

        fixed (byte* p = data)
        {
            madvise(p, (nuint)vpDataSize, MadvHugePage);
            for (long i = 0; i < vpDataSize; i += 4096) _ = p[i];
            mlock(p, (nuint)vpDataSize);
        }

        fixed (byte* ptr = &MemoryMarshal.GetArrayDataReference(data))
        {
            long curr = 0;
            var nodeOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { nodeOffsets[s] = curr; curr += (long)nodeCounts[s] * 64; }

            var leafBlockOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { leafBlockOffsets[s] = curr; curr += (long)leafBlockCounts[s] * sizeof(Block); }

            var leafLabelOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { leafLabelOffsets[s] = curr; curr += (long)leafBlockCounts[s] * 16; }

            var segs = new VpTreeEngine[numSubSegs];
            for (int s = 0; s < numSubSegs; s++)
                segs[s] = new VpTreeEngine(
                    (VpNode*)(ptr + nodeOffsets[s]),
                    (Block*) (ptr + leafBlockOffsets[s]),
                    (byte*)  (ptr + leafLabelOffsets[s]),
                    dimOrder);

            var engine = new SegmentedVpTreeEngine(segs, dimOrder, routeTrees);
            return new MmapData { _engine = engine, FastPath = fastPath, _data = data };
        }
    }

    private static MmapData LoadBB(string path, long fileSize)
    {
        using var fs = File.OpenRead(path);

        int numSubSegs;
        int[] dimOrder;
        int[] nodeCounts, leafBlockCounts;
        RouteNodeRuntime[][] routeTrees256;
        short[][] routeBoxes256;
        short dim8Thresh, dim2Thresh, dim0Q1, dim0Q2, dim0Q3;
        short[] bbMins, bbMaxs;

        {
            using var br = new System.IO.BinaryReader(fs, System.Text.Encoding.UTF8, leaveOpen: true);
            if (br.ReadInt32() != MagicBB) throw new InvalidDataException("VPTC magic mismatch");
            numSubSegs = br.ReadInt32();
            dimOrder = new int[14];
            for (int i = 0; i < 14; i++) dimOrder[i] = br.ReadInt32();
            int numBaseParts = br.ReadInt32();
            if (numBaseParts != 256) throw new InvalidDataException($"VPTB: expected 256 base parts, got {numBaseParts}");

            nodeCounts      = new int[numSubSegs];
            leafBlockCounts = new int[numSubSegs];
            for (int s = 0; s < numSubSegs; s++)
            {
                nodeCounts[s]      = br.ReadInt32();
                leafBlockCounts[s] = br.ReadInt32();
                br.ReadInt32(); // totalVectors
                br.ReadInt32(); // reserved
            }

            var routeNodeCounts = new int[256];
            for (int b = 0; b < 256; b++) routeNodeCounts[b] = br.ReadInt32();

            routeTrees256 = new RouteNodeRuntime[256][];
            for (int b = 0; b < 256; b++)
            {
                routeTrees256[b] = new RouteNodeRuntime[routeNodeCounts[b]];
                for (int n = 0; n < routeNodeCounts[b]; n++)
                    routeTrees256[b][n] = new RouteNodeRuntime
                    {
                        DimReordered = br.ReadInt32(),
                        Threshold    = br.ReadInt32(),
                        LoChild      = br.ReadInt32(),
                        HiChild      = br.ReadInt32(),
                        SegIdx       = br.ReadInt32()
                    };
            }

            // Route node boxes: per node 16 min shorts + 16 max shorts (stride 32).
            routeBoxes256 = new short[256][];
            for (int b = 0; b < 256; b++)
            {
                int cnt = routeNodeCounts[b];
                var arr = new short[cnt * 32];
                for (int i = 0; i < cnt * 32; i++) arr[i] = br.ReadInt16();
                routeBoxes256[b] = arr;
            }

            // Partition thresholds (5 shorts + 1 pad = 12B)
            dim8Thresh = br.ReadInt16();
            dim2Thresh = br.ReadInt16();
            dim0Q1     = br.ReadInt16();
            dim0Q2     = br.ReadInt16();
            dim0Q3     = br.ReadInt16();
            br.ReadInt16(); // pad

            // Bounding boxes: all 256 mins then all 256 maxs (16 shorts each)
            bbMins = new short[256 * 16];
            bbMaxs = new short[256 * 16];
            for (int i = 0; i < 256 * 16; i++) bbMins[i] = br.ReadInt16();
            for (int i = 0; i < 256 * 16; i++) bbMaxs[i] = br.ReadInt16();

            // Zero padding dims so they don't contribute to lower-bound calculation.
            for (int b = 0; b < 256; b++)
            {
                bbMins[b * 16 + 14] = 0; bbMins[b * 16 + 15] = 0;
                bbMaxs[b * 16 + 14] = 0; bbMaxs[b * 16 + 15] = 0;
            }
        }

        long vpDataOffset = fs.Position;
        long vpDataSize   = 0;
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)nodeCounts[s] * 64;
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)leafBlockCounts[s] * sizeof(Block);
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)leafBlockCounts[s] * 16;
        for (int s = 0; s < numSubSegs; s++) vpDataSize += (long)leafBlockCounts[s] * 64; // per-block boxes (32 shorts)

        // Parse + free the fastpath temp buffer BEFORE allocating the large pinned VP-data array,
        // so the two never coexist (keeps the load-time RSS peak under the container limit).
        ProfileFastPath? fastPath = null;
        long fastpathOffset = vpDataOffset + vpDataSize;
        long fastpathSize   = fileSize - fastpathOffset;
        if (fastpathSize > 0)
        {
            fs.Seek(fastpathOffset, SeekOrigin.Begin);
            var fpBytes = new byte[fastpathSize];
            fs.ReadExactly(fpBytes);
            fixed (byte* fpPtr = fpBytes)
                fastPath = ProfileFastPath.LoadFromPointer(fpPtr, fastpathSize);
        }
        GC.Collect(); // reclaim fpBytes before the pinned allocation

        fs.Seek(vpDataOffset, SeekOrigin.Begin);
        var data = GC.AllocateUninitializedArray<byte>((int)vpDataSize, pinned: true);
        fs.ReadExactly(data);

        fixed (byte* p = data)
        {
            madvise(p, (nuint)vpDataSize, MadvHugePage);
            for (long i = 0; i < vpDataSize; i += 4096) _ = p[i];
            mlock(p, (nuint)vpDataSize);
        }

        fixed (byte* ptr = &MemoryMarshal.GetArrayDataReference(data))
        {
            long curr = 0;
            var nodeOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { nodeOffsets[s] = curr; curr += (long)nodeCounts[s] * 64; }

            var leafBlockOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { leafBlockOffsets[s] = curr; curr += (long)leafBlockCounts[s] * sizeof(Block); }

            var leafLabelOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { leafLabelOffsets[s] = curr; curr += (long)leafBlockCounts[s] * 16; }

            var leafBoxOffsets = new long[numSubSegs];
            for (int s = 0; s < numSubSegs; s++) { leafBoxOffsets[s] = curr; curr += (long)leafBlockCounts[s] * 64; }

            var segs = new VpTreeEngine[numSubSegs];
            for (int s = 0; s < numSubSegs; s++)
                segs[s] = new VpTreeEngine(
                    (VpNode*)(ptr + nodeOffsets[s]),
                    (Block*) (ptr + leafBlockOffsets[s]),
                    (byte*)  (ptr + leafLabelOffsets[s]),
                    dimOrder,
                    (short*) (ptr + leafBoxOffsets[s]));

            var engine = new SegmentedVpTreeEngine(segs, dimOrder, routeTrees256, routeBoxes256, bbMins, bbMaxs,
                dim8Thresh, dim2Thresh, dim0Q1, dim0Q2, dim0Q3);
            return new MmapData { _engine = engine, FastPath = fastPath, _data = data };
        }
    }
}
