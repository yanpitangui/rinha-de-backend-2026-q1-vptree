using FraudApi.Shared;

namespace FraudApi.Data;

using System.IO.MemoryMappedFiles;

public sealed unsafe class MmapData
{
    public Block* Blocks;
    public byte* Labels;
    public int BlockCount;
    public int Total;

    private MemoryMappedFile _mmf;
    private MemoryMappedViewAccessor _accessor;

    public static MmapData Load(string path)
    {
        var mmf = MemoryMappedFile.CreateFromFile(path);
        var accessor = mmf.CreateViewAccessor();

        byte* ptr = null;
        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);

        int blockCount = *(int*)ptr;
        int total = *(int*)(ptr + 4);

        byte* dataStart = ptr + 8;

        var blocks = (Block*)dataStart;
        var labels = dataStart + sizeof(Block) * blockCount;

        return new MmapData
        {
            Blocks = blocks,
            Labels = labels,
            BlockCount = blockCount,
            Total = total,
            _mmf = mmf,
            _accessor = accessor
        };
    }
}