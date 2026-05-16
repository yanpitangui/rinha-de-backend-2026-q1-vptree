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

var nprobe = int.TryParse(Environment.GetEnvironmentVariable("NPROBE"), out var np) ? np : 1;
var nprobeRetry = int.TryParse(Environment.GetEnvironmentVariable("NPROBE_RETRY"), out var nr) ? nr : 64;
var nprobeExhaust = int.TryParse(Environment.GetEnvironmentVariable("NPROBE_EXHAUST"), out var ne) ? ne : 512;

unsafe
{
    var mmap = MmapData.Load(Path.Combine(resourcesPath, "dataset.bin"));
    FraudHandler.MmapRef = mmap;
    FraudHandler.Engine = new SearchEngine(
        mmap.Blocks, mmap.Labels, mmap.Centroids,
        mmap.ClusterBlockStart, mmap.ClusterBlockLen,
        mmap.BboxMin, mmap.BboxMax, mmap.K,
        nprobe, nprobeRetry, nprobeExhaust, mmap.DimOrder
    );
}

FraudHandler.MccRisk = mccRisk;
FraudHandler.Norm = normalization;
FraudHandler.Responses = BuildResponses();

var fastPathFile = Path.Combine(resourcesPath, "fastpath.bin");
if (File.Exists(fastPathFile))
    FraudHandler.FastPath = ProfileFastPath.Load(fastPathFile);

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
