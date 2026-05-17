using System.Runtime.InteropServices;
using FraudApi.Shared;

namespace FraudApi.Data;

public sealed unsafe class MmapData
{
    public Block* Blocks;
    public byte* Labels;
    public short* BboxMin; // K * 14 shorts
    public short* BboxMax; // K * 14 shorts
    public int BlockCount;
    public int Total;
    public int K;
    public float[] Centroids = null!;
    public int[] ClusterBlockStart = null!;
    public int[] ClusterBlockLen = null!;
    public int[] DimOrder = null!; // 14 dim indices sorted by variance descending

    private byte[] _data = null!;

    public static MmapData Load(string path)
    {
        var fileSize = (int)new FileInfo(path).Length;
        var data = GC.AllocateUninitializedArray<byte>(fileSize, pinned: true);
        using var fs = File.OpenRead(path);
        fs.ReadExactly(data);

        fixed (byte* ptr = &MemoryMarshal.GetArrayDataReference(data))
        {
            int blockCount = *(int*)(ptr + 4);
            int total      = *(int*)(ptr + 8);
            int k          = *(int*)(ptr + 12);

            // dimOrder: 14 ints at offset 16
            int* dimOrderPtr = (int*)(ptr + 16);
            var dimOrder = new int[14];
            new ReadOnlySpan<int>(dimOrderPtr, 14).CopyTo(dimOrder);

            // centroids column-major [dim][centroid]: after dimOrder (offset 16 + 14*4 = 72)
            float* centroidPtr = (float*)(ptr + 72);
            int centroidFloats = 14 * k;
            var centroids = new float[centroidFloats];
            new ReadOnlySpan<float>(centroidPtr, centroidFloats).CopyTo(centroids);

            int* blockStartPtr = (int*)(centroidPtr + centroidFloats);
            var clusterBlockStart = new int[k];
            new ReadOnlySpan<int>(blockStartPtr, k).CopyTo(clusterBlockStart);

            int* blockLenPtr = blockStartPtr + k;
            var clusterBlockLen = new int[k];
            new ReadOnlySpan<int>(blockLenPtr, k).CopyTo(clusterBlockLen);

            short* bboxMinPtr = (short*)(blockLenPtr + k);
            short* bboxMaxPtr = bboxMinPtr + k * 14;

            byte* dataStart = (byte*)(bboxMaxPtr + k * 14);
            var blocks = (Block*)dataStart;
            var labels = dataStart + (long)sizeof(Block) * blockCount;

            return new MmapData
            {
                Blocks = blocks,
                Labels = labels,
                BboxMin = bboxMinPtr,
                BboxMax = bboxMaxPtr,
                BlockCount = blockCount,
                Total = total,
                K = k,
                Centroids = centroids,
                ClusterBlockStart = clusterBlockStart,
                ClusterBlockLen = clusterBlockLen,
                DimOrder = dimOrder,
                _data = data
            };
        }
    }
}
