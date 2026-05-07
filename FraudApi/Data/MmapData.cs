using System.Runtime.InteropServices;
using FraudApi.Shared;

namespace FraudApi.Data;

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

    private byte[] _data = null!;

    public static MmapData Load(string path)
    {
        var raw = File.ReadAllBytes(path);
        var data = GC.AllocateUninitializedArray<byte>(raw.Length, pinned: true);
        raw.AsSpan().CopyTo(data);

        fixed (byte* ptr = &MemoryMarshal.GetArrayDataReference(data))
        {
            int blockCount = *(int*)(ptr + 4);
            int total      = *(int*)(ptr + 8);
            int k          = *(int*)(ptr + 12);

            float* centroidPtr = (float*)(ptr + 16);
            var centroids = new float[k * 16];
            new ReadOnlySpan<float>(centroidPtr, k * 16).CopyTo(centroids);

            int* blockStartPtr = (int*)(centroidPtr + k * 16);
            var clusterBlockStart = new int[k];
            new ReadOnlySpan<int>(blockStartPtr, k).CopyTo(clusterBlockStart);

            int* blockLenPtr = blockStartPtr + k;
            var clusterBlockLen = new int[k];
            new ReadOnlySpan<int>(blockLenPtr, k).CopyTo(clusterBlockLen);

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
                _data = data
            };
        }
    }
}
