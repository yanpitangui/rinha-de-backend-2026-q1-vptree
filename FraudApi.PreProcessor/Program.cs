using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using FraudApi.Shared;

const int   Scale           = 10000;
const int   Dims            = 14;
const int   BucketSize      = 128;
const int   VpSampleSize    = 20;         // candidates sampled per node for vantage point selection
const int   Magic           = 0x56505454; // "VPTT"
const short PaddingSentinel = short.MaxValue; // well outside [0,Scale] → guaranteed large distance → never enters heap

var resourcesPath =
    args.Length > 0
        ? args[0]
        : Environment.GetEnvironmentVariable("RESOURCES_PATH")
        ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var input  = Path.Combine(resourcesPath, "references.json.gz");
var output = Path.Combine(resourcesPath, "vptree.bin");

Console.WriteLine($"Loading dataset from: {input}");

// ── Phase 1: stream all vectors ───────────────────────────────────────────
const int MaxVectors = 3_100_000;
var allVecs   = new short[MaxVectors * 16];
var allLabels = new byte[MaxVectors];
int total = 0;

{
    using var fs = File.OpenRead(input);
    using var gz = new GZipStream(fs, CompressionMode.Decompress);

    byte[] buffer     = new byte[64 * 1024];
    int bytesInBuffer = 0;
    var state         = new JsonReaderState();

    double[] vec = new double[Dims];
    bool inVector = false;
    int vi = 0;
    bool isFraud = false, vecComplete = false;

    void ProcessToken(ref Utf8JsonReader r)
    {
        switch (r.TokenType)
        {
            case JsonTokenType.PropertyName:
                var n = r.GetString();
                if (n == "vector") { r.Read(); inVector = true; vi = 0; }
                else if (n == "label") { r.Read(); isFraud = r.GetString() == "fraud"; }
                break;
            case JsonTokenType.Number when inVector:
                vec[vi++] = r.GetDouble();
                break;
            case JsonTokenType.EndArray when inVector:
                inVector = false; vecComplete = true;
                break;
            case JsonTokenType.EndObject when vecComplete:
                int @base = total * 16;
                for (int d = 0; d < Dims; d++)
                    allVecs[@base + d] = Quantize(vec[d]);
                allLabels[total] = isFraud ? (byte)1 : (byte)0;
                total++;
                vecComplete = false; isFraud = false;
                break;
        }
    }

    while (true)
    {
        int bytesRead = gz.Read(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
        if (bytesRead == 0) break;
        bytesInBuffer += bytesRead;
        var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(buffer, 0, bytesInBuffer), false, state);
        while (reader.Read()) ProcessToken(ref reader);
        int consumed = (int)reader.BytesConsumed;
        Buffer.BlockCopy(buffer, consumed, buffer, 0, bytesInBuffer - consumed);
        bytesInBuffer -= consumed;
        state = reader.CurrentState;
    }
    var finalReader = new Utf8JsonReader(new ReadOnlySpan<byte>(buffer, 0, bytesInBuffer), true, state);
    while (finalReader.Read()) ProcessToken(ref finalReader);
}

Console.WriteLine($"Loaded {total} vectors. Computing dim variance...");

// ── Phase 2: per-dim variance → dimOrder ─────────────────────────────────
var mean = new double[Dims];
var m2   = new double[Dims];
for (int i = 0; i < total; i++)
{
    int vb = i * 16;
    for (int d = 0; d < Dims; d++)
    {
        double x     = allVecs[vb + d];
        double delta = x - mean[d];
        mean[d] += delta / (i + 1);
        m2[d]   += delta * (x - mean[d]);
    }
}
var dimVariance = new double[Dims];
for (int d = 0; d < Dims; d++) dimVariance[d] = m2[d] / total;
var dimOrder = Enumerable.Range(0, Dims).OrderByDescending(d => dimVariance[d]).ToArray();
Console.WriteLine($"Dim order (high→low variance): [{string.Join(", ", dimOrder)}]");

// ── Phase 3: build VP-tree ────────────────────────────────────────────────
Console.WriteLine("Building VP-tree...");

var rng          = new Random(42);
var nodes        = new List<VpNode>();
int leafBlockCount = 0;

// Leaf data buffered to streams — written after nodes in the final file
var leafBlocksMs = new MemoryStream();
var leafLabelsMs = new MemoryStream();
var bwLB = new BinaryWriter(leafBlocksMs);
var bwLL = new BinaryWriter(leafLabelsMs);

var allIndices = new int[total];
for (int i = 0; i < total; i++) allIndices[i] = i;
BuildNode(allIndices);

bwLB.Flush(); bwLL.Flush();

int nodeCount = nodes.Count;
Console.WriteLine($"VP-tree built: {nodeCount} nodes, {leafBlockCount} leaf blocks");

// ── Phase 4: write vptree.bin ─────────────────────────────────────────────
// Layout:
//   [4B] magic  [4B] N  [4B] nodeCount  [4B] bucketSize  [4B] leafBlockCount
//   [14×4B] dimOrder
//   nodes:      nodeCount × 64B (VpNode with inline VP vector)
//   leafBlocks: leafBlockCount × sizeof(Block) (= ×224B, column-major 8-wide)
//   leafLabels: leafBlockCount × 8B

using var bw = new BinaryWriter(File.Create(output));
bw.Write(Magic);
bw.Write(total);
bw.Write(nodeCount);
bw.Write(BucketSize);
bw.Write(leafBlockCount);
foreach (var d in dimOrder) bw.Write(d);

foreach (var nd in nodes)
{
    // Binary layout must match runtime VpNode [StructLayout(Sequential, Pack=2, Size=64)]:
    //   int Left      @ 0  (4B)
    //   int Right     @ 4  (4B)
    //   float Thresh  @ 8  (4B)
    //   byte VpLabel  @ 12 (1B)
    //   byte Hi       @ 13 (1B)
    //   int VpOrCnt   @ 14 (4B)  [Pack=2 → no gap after byte]
    //   short Vp[14]  @ 18 (28B)
    //   padding       @ 46 (18B) → total 64B
    bw.Write(nd.Left);
    bw.Write(nd.Right);
    bw.Write(nd.Threshold);
    bw.Write(nd.VpLabel);
    bw.Write((byte)0);          // BlockCountHi (unused)
    bw.Write(nd.VpIdxOrCount);
    if (nd.Vp != null)
        foreach (var v in nd.Vp) bw.Write(v);
    else
        for (int i = 0; i < Dims; i++) bw.Write((short)0);
    for (int i = 0; i < 18; i++) bw.Write((byte)0); // pad to 64B
}

var leafBlocksBytes = leafBlocksMs.ToArray();
var leafLabelsBytes = leafLabelsMs.ToArray();
bw.Write(leafBlocksBytes);
bw.Write(leafLabelsBytes);
bw.Flush();

Console.WriteLine($"Written {output} ({new FileInfo(output).Length / 1024.0 / 1024.0:F1} MiB)");

// ── Phase 5: build profile fast-path table ────────────────────────────────
Console.WriteLine("Building profile fast-path table...");
BuildFastPath(allVecs, allLabels, total, resourcesPath);

// ── VP-tree build helpers ─────────────────────────────────────────────────

int BuildNode(int[] indices)
{
    int nodeIdx = nodes.Count;
    nodes.Add(default);

    if (indices.Length <= BucketSize)
    {
        // Leaf: pack into column-major Block(s) of 8
        int blockStart = leafBlockCount;
        int nBlocks    = (indices.Length + 7) / 8;

        for (int bi = 0; bi < nBlocks; bi++)
        {
            // 14 dims × 8 positions (column-major = Block layout)
            for (int di = 0; di < Dims; di++)
                for (int pos = 0; pos < 8; pos++)
                {
                    int mi = bi * 8 + pos;
                    short v = mi < indices.Length
                        ? allVecs[indices[mi] * 16 + dimOrder[di]]
                        : PaddingSentinel;
                    bwLB.Write(v);
                }
            // Labels for this block's 8 slots
            for (int pos = 0; pos < 8; pos++)
            {
                int mi = bi * 8 + pos;
                bwLL.Write(mi < indices.Length ? allLabels[indices[mi]] : (byte)0);
            }
        }
        leafBlockCount += nBlocks;

        nodes[nodeIdx] = new VpNode { VpIdxOrCount = nBlocks, Left = blockStart, Right = -1 };
        return nodeIdx;
    }

    // Internal node
    int vpGlobalIdx = PickVantagePoint(indices);

    // Partition non-VP points by distance to VP
    int nonVpCount = indices.Length - 1;
    var distPairs  = new (int idx, long dsq)[nonVpCount];
    int di2 = 0;
    foreach (var idx in indices)
        if (idx != vpGlobalIdx)
            distPairs[di2++] = (idx, DistSqInt64(idx, vpGlobalIdx));
    Array.Sort(distPairs, (a, b) => a.dsq.CompareTo(b.dsq));

    int mid = Math.Max(1, nonVpCount / 2);

    if (mid >= nonVpCount)
    {
        // Degenerate: fall back to leaf with all including VP
        int blockStart = leafBlockCount;
        int nBlocks    = (indices.Length + 7) / 8;
        for (int bi = 0; bi < nBlocks; bi++)
        {
            for (int di = 0; di < Dims; di++)
                for (int pos = 0; pos < 8; pos++)
                {
                    int mi = bi * 8 + pos;
                    short v = mi < indices.Length
                        ? allVecs[indices[mi] * 16 + dimOrder[di]]
                        : PaddingSentinel;
                    bwLB.Write(v);
                }
            for (int pos = 0; pos < 8; pos++)
            {
                int mi = bi * 8 + pos;
                bwLL.Write(mi < indices.Length ? allLabels[indices[mi]] : (byte)0);
            }
        }
        leafBlockCount += nBlocks;
        nodes[nodeIdx] = new VpNode { VpIdxOrCount = nBlocks, Left = blockStart, Right = -1 };
        return nodeIdx;
    }

    float mu = MathF.Sqrt((float)distPairs[mid - 1].dsq) / Scale;

    var leftArr  = new int[mid];
    var rightArr = new int[nonVpCount - mid];
    for (int i = 0;   i < mid;        i++) leftArr[i]        = distPairs[i].idx;
    for (int i = mid; i < nonVpCount; i++) rightArr[i - mid] = distPairs[i].idx;

    int leftChild  = BuildNode(leftArr);
    int rightChild = BuildNode(rightArr);

    var vp = new short[Dims];
    for (int di = 0; di < Dims; di++)
        vp[di] = allVecs[vpGlobalIdx * 16 + dimOrder[di]];

    nodes[nodeIdx] = new VpNode
    {
        Left = leftChild, Right = rightChild,
        Threshold = mu, VpLabel = allLabels[vpGlobalIdx],
        VpIdxOrCount = 0, Vp = vp
    };
    return nodeIdx;
}

int PickVantagePoint(int[] indices)
{
    int sampleSize = Math.Min(VpSampleSize, indices.Length);
    var sample     = new int[sampleSize];
    for (int i = 0; i < sampleSize; i++) sample[i] = indices[i];
    for (int i = sampleSize; i < indices.Length; i++)
    {
        int j = rng.Next(i + 1);
        if (j < sampleSize) sample[j] = indices[i];
    }
    int bestVp = sample[0];
    long bestSum = long.MinValue;
    for (int i = 0; i < sampleSize; i++)
    {
        long sum = 0;
        for (int j = 0; j < sampleSize; j++)
            if (i != j) sum += DistSqInt64(sample[i], sample[j]);
        if (sum > bestSum) { bestSum = sum; bestVp = sample[i]; }
    }
    return bestVp;
}

long DistSqInt64(int aIdx, int bIdx)
{
    long acc = 0;
    int ab = aIdx * 16, bb = bIdx * 16;
    for (int d = 0; d < Dims; d++)
    {
        int diff = allVecs[ab + d] - allVecs[bb + d];
        acc += diff * diff;
    }
    return acc;
}

// ── Shared helpers ────────────────────────────────────────────────────────

static short Quantize(double v)
{
    var q = (int)Math.Round(v * Scale);
    if (q > short.MaxValue) q = short.MaxValue;
    if (q < short.MinValue) q = short.MinValue;
    return (short)q;
}

static void BuildFastPath(short[] allVecs, byte[] allLabels, int total, string resourcesPath)
{
    int[] featureIndex = [6,  2,  5, 0, 12, 7, 9, 10, 11];
    int[] bits         = [6,  4,  3, 3,  2, 2, 1,  1,  1]; // sum=23 → 8M entries × 2B = 16 MiB

    int nf        = featureIndex.Length;
    int tableSize = 1 << bits.Sum();

    var shifts = new int[nf];
    for (int f = 1; f < nf; f++) shifts[f] = shifts[f - 1] + bits[f - 1];

    var edges = new short[nf][];
    for (int f = 0; f < nf; f++)
    {
        int dim      = featureIndex[f];
        int numBins  = 1 << bits[f];
        int numEdges = numBins - 1;
        var values   = new short[total];
        for (int i = 0; i < total; i++) values[i] = allVecs[i * 16 + dim];
        Array.Sort(values);
        edges[f] = new short[numEdges];
        for (int b = 0; b < numEdges; b++)
        {
            int pos = (int)((long)(b + 1) * total / numBins);
            edges[f][b] = values[pos];
        }
    }

    var buckets = new Dictionary<uint, ulong>(1 << 20);
    for (int i = 0; i < total; i++)
    {
        uint key = 0;
        for (int f = 0; f < nf; f++)
            key |= (uint)FindBinS(edges[f], allVecs[i * 16 + featureIndex[f]]) << shifts[f];
        ulong cur = buckets.TryGetValue(key, out var c) ? c : 0UL;
        buckets[key] = cur + (1UL << 32) + allLabels[i];
    }

    var table = new ushort[tableSize];
    foreach (var kv in buckets)
    {
        long totalL = (long)(kv.Value >> 32);
        long fraudL = (long)(kv.Value & 0xFFFFFFFF);
        long legitL = totalL - fraudL;
        table[kv.Key] = (ushort)(((uint)Math.Min(legitL, 255) << 8) | (uint)Math.Min(fraudL, 255));
    }

    // Must match ProfileFastPath.cs defaults (domLegit disabled = int.MaxValue)
    const int defPureLegitMin = 100, defPureFraudMin = 20, defDomFraudMin = 100;
    long hitsPureLegit = 0, hitsPureFraud = 0, hitsDom = 0;
    foreach (var kv in buckets)
    {
        long totalL = (long)(kv.Value >> 32);
        long fraudL = (long)(kv.Value & 0xFFFFFFFF);
        long legitL = totalL - fraudL;
        if (fraudL == 0 && totalL >= defPureLegitMin)               hitsPureLegit += totalL;
        else if (legitL == 0 && totalL >= defPureFraudMin)          hitsPureFraud += totalL;
        else if (legitL == 1 && totalL >= defDomFraudMin)           hitsDom       += totalL; // domFraud only
    }
    long totalHits = hitsPureLegit + hitsPureFraud + hitsDom;
    Console.WriteLine($"  Fast-path coverage: {totalHits * 100.0 / total:F1}%  " +
                      $"(pure-legit={hitsPureLegit}, pure-fraud={hitsPureFraud}, dominant={hitsDom})");

    var outputPath = Path.Combine(resourcesPath, "fastpath.bin");
    using var bw2 = new BinaryWriter(File.Create(outputPath));
    bw2.Write(unchecked((int)0x46415333));
    for (int f = 0; f < nf; f++)
    {
        bw2.Write(edges[f].Length);
        foreach (var e in edges[f]) bw2.Write(e);
    }
    bw2.Write(tableSize);
    foreach (var v in table) bw2.Write(v);
    Console.WriteLine($"  Written {outputPath} ({new FileInfo(outputPath).Length / 1024.0 / 1024.0:F1} MiB)");
}

static int FindBinS(short[] edges, short v)
{
    for (int b = 0; b < edges.Length; b++)
        if (v < edges[b]) return b;
    return edges.Length;
}

[StructLayout(LayoutKind.Sequential)]
struct VpNode
{
    public int    Left;
    public int    Right;
    public float  Threshold;
    public byte   VpLabel;
    public int    VpIdxOrCount; // leaf: block count; internal: 0
    public short[]? Vp;         // internal: 14 shorts (variance-ordered); null for leaves
}
