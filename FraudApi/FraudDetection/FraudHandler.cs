using FraudApi.Config;

namespace FraudApi.FraudDetection;

public static class FraudHandler
{
    public static SearchEngine Engine = default!;
    public static Dictionary<int, double> MccRisk = default!;
    public static NormalizationConfig Norm = default!;
    public static byte[][] Responses = default!;

    public static IResult Handle(FraudRequest req)
    {
        Span<short> query = stackalloc short[16];
        Vectorizer.Vectorize(req, query, MccRisk, Norm);
        int fraudCount = Engine.Search(query);
        return Results.Bytes(Responses[fraudCount], "application/json");
    }
}