using FraudApi.Config;
using FraudApi.Data;

namespace FraudApi.FraudDetection;

public static class FraudHandler
{
    public static SearchEngine Engine = default!;
    public static Dictionary<int, double> MccRisk = default!;
    public static NormalizationConfig Norm = default!;
    public static byte[][] Responses = default!;
    public static ProfileFastPath? FastPath;
    // Keeps pinned dataset array alive — without this the GC can collect mmap._data
    // once the local var in Program.cs goes out of scope, dangling Block*/byte* → AV.
    public static MmapData MmapRef = default!;
}