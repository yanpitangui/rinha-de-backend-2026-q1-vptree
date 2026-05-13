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

    public static IResult Handle(FraudRequest req)
    {
        Span<short> query = stackalloc short[16];
        Vectorizer.Vectorize(req, query, MccRisk, Norm);

        if (FastPath is { } fp)
        {
            byte hit = fp.TryLookup(query);
            if (hit == 2) return Results.Bytes(Responses[5], "application/json"); // pure fraud
            // hit==1 (pure legit) falls through to IVF — avoids FN on out-of-distribution fraud
        }

        int fraudCount = Engine.Search(query);
        return Results.Bytes(Responses[fraudCount], "application/json");
    }
}