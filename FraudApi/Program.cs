using System.Text.Json;
using System.Text.Json.Serialization;
using FraudApi.Config;
using FraudApi.Data;
using FraudApi.FraudDetection;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var resourcesPath = Environment.GetEnvironmentVariable("RESOURCES_PATH")
                    ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var mccRaw = JsonSerializer.Deserialize(
    File.ReadAllText(Path.Combine(resourcesPath, "mcc_risk.json")),
    AppJsonSerializerContext.Default.DictionaryStringSingle
)!;

var mccRisk = new Dictionary<int, float>(mccRaw.Count);
foreach (var kv in mccRaw)
{
    mccRisk[int.Parse((string)kv.Key)] = kv.Value;
}

var normalization = JsonSerializer.Deserialize(
    File.ReadAllText(Path.Combine(resourcesPath, "normalization.json")),
    AppJsonSerializerContext.Default.NormalizationConfig
)!;

unsafe
{
    var mmap = MmapData.Load(Path.Combine(resourcesPath, "dataset.bin"));

    FraudHandler.Engine = new SearchEngine(
        mmap.Blocks,
        mmap.Labels,
        mmap.BlockCount
    );
}


FraudHandler.MccRisk = mccRisk;
FraudHandler.Norm = normalization;
FraudHandler.Responses = BuildResponses();

var app = builder.Build();

app.MapGet("/ready", () => Results.Ok());

app.MapPost("/fraud-score", FraudHandler.Handle);

app.Run();

static byte[][] BuildResponses()
{
    var arr = new byte[6][];

    for (int i = 0; i <= 5; i++)
    {
        float score = i / 5f;
        string json = $"{{\"approved\":{(score < 0.6f).ToString().ToLower()},\"fraud_score\":{score}}}";
        arr[i] = System.Text.Encoding.UTF8.GetBytes(json);
    }

    return arr;
}

[JsonSerializable(typeof(FraudRequest))]
[JsonSerializable(typeof(NormalizationConfig))]
[JsonSerializable(typeof(Dictionary<string, float>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}