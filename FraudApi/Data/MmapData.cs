using FraudApi.Shared;

namespace FraudApi.Data;

using System.IO.MemoryMappedFiles;

public sealed unsafe class MmapData
{
    public Block* Blocks;
    public byte* Labels;
    public int BlockCount;
    public int Total;
    public int K;
    public float[] Centroids = null!;
    public int[] ClusterBlockStart = null!;
    public int[] ClusterBlockLen = null!;

    private MemoryMappedFile _mmf = null!;
    private MemoryMappedViewAccessor _accessor = null!;

    public static MmapData Load(string path)
    {
        var mmf = MemoryMappedFile.CreateFromFile(path);
        var accessor = mmf.CreateViewAccessor();

        byte* ptr = null;
        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);

        // IVF2 header: Magic(4) BlockCount(4) Total(4) K(4)
        int blockCount = *(int*)(ptr + 4);
        int total      = *(int*)(ptr + 8);
        int k          = *(int*)(ptr + 12);

        // Centroids: K * 16 floats
        float* centroidPtr = (float*)(ptr + 16);
        var centroids = new float[k * 16];
        new ReadOnlySpan<float>(centroidPtr, k * 16).CopyTo(centroids);

        // ClusterBlockStart: K ints
        int* blockStartPtr = (int*)(centroidPtr + k * 16);
        var clusterBlockStart = new int[k];
        new ReadOnlySpan<int>(blockStartPtr, k).CopyTo(clusterBlockStart);

        // ClusterBlockLen: K ints
        int* blockLenPtr = blockStartPtr + k;
        var clusterBlockLen = new int[k];
        new ReadOnlySpan<int>(blockLenPtr, k).CopyTo(clusterBlockLen);

        // Blocks then labels
        byte* dataStart = (byte*)(blockLenPtr + k);
        var blocks = (Block*)dataStart;
        var labels = dataStart + (long)sizeof(Block) * blockCount;

        return new MmapData
        {
            Blocks = blocks,
            Labels = labels,
            BlockCount = blockCount,
            Total = total,
            K = k,
            Centroids = centroids,
            ClusterBlockStart = clusterBlockStart,
            ClusterBlockLen = clusterBlockLen,
            _mmf = mmf,
            _accessor = accessor
        };
    }
}
