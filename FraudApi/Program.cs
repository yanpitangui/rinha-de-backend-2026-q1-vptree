using System.Runtime;
using System.Text.Json;
using System.Text.Json.Serialization;
using FraudApi.Config;
using FraudApi.Data;
using FraudApi.FraudDetection;
using FraudApi.Transport;

GCSettings.LatencyMode = GCLatencyMode.SustainedLowLatency;

var minWorkers = int.TryParse(Environment.GetEnvironmentVariable("TP_MIN_WORKERS"), out var minW) ? minW : 8;
var minIoThreads = int.TryParse(Environment.GetEnvironmentVariable("TP_MIN_IO"), out var minIo) ? minIo : 64;
ThreadPool.SetMinThreads(minWorkers, minIoThreads);
ThreadPool.SetMaxThreads(minWorkers, minIoThreads);

var resourcesPath = Environment.GetEnvironmentVariable("RESOURCES_PATH")
    ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var mccRaw = JsonSerializer.Deserialize(
    File.ReadAllText(Path.Combine(resourcesPath, "mcc_risk.json")),
    AppJsonSerializerContext.Default.DictionaryStringDouble
)!;
var mccRisk = new Dictionary<int, double>(mccRaw.Count);
foreach (var kv in mccRaw) mccRisk[int.Parse(kv.Key)] = kv.Value;

var normalization = JsonSerializer.Deserialize(
    File.ReadAllText(Path.Combine(resourcesPath, "normalization.json")),
    AppJsonSerializerContext.Default.NormalizationConfig
)!;

var mmap = MmapData.Load(Path.Combine(resourcesPath, "vptree.bin"));
FraudHandler.MmapRef = mmap;
FraudHandler.Engine  = mmap.CreateEngine();

FraudHandler.MccRisk   = mccRisk;
FraudHandler.Norm      = normalization;
DirectHandler.Init(normalization);
FraudHandler.Responses = BuildResponses();

var mccLut = new short[10000];
Array.Fill(mccLut, DirectHandler.Q(0.5f));
foreach (var kv in mccRisk)
    if ((uint)kv.Key < 10000u)
        mccLut[kv.Key] = DirectHandler.Q((float)kv.Value);
FraudHandler.MccLut = mccLut;

FraudHandler.FastPath = mmap.FastPath;

// Warmup: prime branch predictor + CPU caches for all 16 segments before serving.
// Original 200-query loop only hit segs 8-15 (dim5 always >=0 → has_last_tx=true).
// Segs 0-7 (no last_tx, dim5=dim6=-10000) were completely cold.
{
    var rng = new Random(42);
    Span<short> q = stackalloc short[16];
    const int WarmupPerSeg = 50;
    for (int seg = 0; seg < 16; seg++)
    {
        bool hasLastTx    = (seg & 8) != 0;
        bool isOnline     = (seg & 4) != 0;
        bool cardPresent  = (seg & 2) != 0;
        bool unknownMerch = (seg & 1) != 0;
        for (int i = 0; i < WarmupPerSeg; i++)
        {
            for (int d = 0; d < 14; d++) q[d] = (short)rng.Next(0, 10001);
            q[5]  = hasLastTx    ? (short)rng.Next(0, 10001) : (short)(-10000);
            q[6]  = hasLastTx    ? (short)rng.Next(0, 10001) : (short)(-10000);
            q[9]  = isOnline     ? (short)10000 : (short)0;
            q[10] = cardPresent  ? (short)10000 : (short)0;
            q[11] = unknownMerch ? (short)10000 : (short)0;
            FraudHandler.Engine.Search(q);
        }
    }
}

var socketPath = $"/sockets/{System.Net.Dns.GetHostName()}.sock";
RawServer.Run(socketPath);

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

[JsonSerializable(typeof(NormalizationConfig))]
[JsonSerializable(typeof(Dictionary<string, double>))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }
