using FraudApi.Config;

namespace FraudApi.FraudDetection;

public static class FraudHandler
{
    public static SearchEngine Engine = default!;
    public static Dictionary<int, float> MccRisk = default!;
    public static NormalizationConfig Norm = default!;
    public static byte[][] Responses = default!;

    public static IResult Handle(FraudRequest req)
    {
        Span<float> features = stackalloc float[14];
        Span<short> query = stackalloc short[16];

        FeatureExtractor.Extract(req, features, MccRisk);
        Normalizer.Normalize(features, Norm);
        Vectorizer.Vectorize(features, query);

        int fraudCount = Engine.Search(query);

        return Results.Bytes(Responses[fraudCount]);
    }
}