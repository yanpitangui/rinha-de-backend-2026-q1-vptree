using System.Runtime;
using System.Text.Json;
using System.Text.Json.Serialization;
using FraudApi.Config;
using FraudApi.Data;
using FraudApi.FraudDetection;

GCSettings.LatencyMode = GCLatencyMode.SustainedLowLatency;

var minWorkers = int.TryParse(Environment.GetEnvironmentVariable("TP_MIN_WORKERS"), out var minW) ? minW : 16;
var maxWorkers = int.TryParse(Environment.GetEnvironmentVariable("TP_MAX_WORKERS"), out var maxW) ? maxW : 16;
ThreadPool.SetMinThreads(minWorkers, minWorkers);
ThreadPool.SetMaxThreads(maxWorkers, maxWorkers);

var builder = WebApplication.CreateSlimBuilder(args);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 4096;
    options.Limits.MaxConcurrentConnections = 2048;
    options.Limits.MaxConcurrentUpgradedConnections = 1024;

    var socketPath = $"/sockets/{System.Net.Dns.GetHostName()}.sock";
    if (Directory.Exists("/sockets"))
    {
        if (File.Exists(socketPath)) File.Delete(socketPath);
        options.ListenUnixSocket(socketPath);
    }
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var resourcesPath = Environment.GetEnvironmentVariable("RESOURCES_PATH")
                    ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var mccRaw = JsonSerializer.Deserialize(
    File.ReadAllText(Path.Combine(resourcesPath, "mcc_risk.json")),
    AppJsonSerializerContext.Default.DictionaryStringDouble
)!;

var mccRisk = new Dictionary<int, double>(mccRaw.Count);
foreach (var kv in mccRaw)
    mccRisk[int.Parse(kv.Key)] = kv.Value;

var normalization = JsonSerializer.Deserialize(
    File.ReadAllText(Path.Combine(resourcesPath, "normalization.json")),
    AppJsonSerializerContext.Default.NormalizationConfig
)!;

var nprobe = int.TryParse(Environment.GetEnvironmentVariable("NPROBE"), out var np) ? np : 1;
var nprobeRetry = int.TryParse(Environment.GetEnvironmentVariable("NPROBE_RETRY"), out var nr) ? nr : 64;
var nprobeExhaust = int.TryParse(Environment.GetEnvironmentVariable("NPROBE_EXHAUST"), out var ne) ? ne : 512;

unsafe
{
    var mmap = MmapData.Load(Path.Combine(resourcesPath, "dataset.bin"));

    FraudHandler.Engine = new SearchEngine(
        mmap.Blocks,
        mmap.Labels,
        mmap.Centroids,
        mmap.ClusterBlockStart,
        mmap.ClusterBlockLen,
        mmap.BboxMin,
        mmap.BboxMax,
        mmap.K,
        nprobe,
        nprobeRetry,
        nprobeExhaust,
        mmap.DimOrder
    );
}


FraudHandler.MccRisk = mccRisk;
FraudHandler.Norm = normalization;
FraudHandler.Responses = BuildResponses();

var app = builder.Build();

app.MapGet("/ready", () => Results.Ok());

app.MapPost("/fraud-score", FraudHandler.Handle);

// chmod the socket so nginx can access it
var socketPath = $"/sockets/{System.Net.Dns.GetHostName()}.sock";
if (Directory.Exists("/sockets"))
{
    _ = Task.Run(async () =>
    {
        while (!File.Exists(socketPath)) await Task.Delay(50);
        System.Diagnostics.Process.Start("chmod", $"777 {socketPath}")?.WaitForExit();
    });
}

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
[JsonSerializable(typeof(Dictionary<string, double>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}