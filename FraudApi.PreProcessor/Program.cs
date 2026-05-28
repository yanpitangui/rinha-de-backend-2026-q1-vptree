using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using FraudApi.Shared;

const int   Scale           = 10000;
const int   Dims            = 14;
int         BucketSize      = int.TryParse(Environment.GetEnvironmentVariable("BUCKET_SIZE"), out var bs) ? bs : 1024;
int         VpSampleSize    = int.TryParse(Environment.GetEnvironmentVariable("VP_SAMPLE_SIZE"), out var vps) ? vps : 20;
const short PaddingSentinel = short.MaxValue; // well outside [0,Scale] → guaranteed large distance → never enters heap

var resourcesPath =
    args.Length > 0
        ? args[0]
        : Environment.GetEnvironmentVariable("RESOURCES_PATH")
        ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var input  = Path.Combine(resourcesPath, "references.json.gz");
var output = Path.Combine(resourcesPath, "vptree.bin");

Console.WriteLine($"Loading dataset from: {input}");

// Phase 1: stream all vectors
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

// Phase 2: per-dim variance → dimOrder
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
Console.WriteLine($"Dim order (high->low variance): [{string.Join(", ", dimOrder)}]");

// Phase 3: KD-routing VP-tree.
// Each base seg (0-15) is recursively split by highest-variance continuous dim
// until sub-seg size ≤ MaxLeafSeg. Each leaf sub-seg gets its own VP-tree.
// Magic 0x56505454 "VPTT".
int MaxLeafSeg = int.TryParse(Environment.GetEnvironmentVariable("MAX_LEAF_SEG"), out var ml) ? ml : 16384;
Console.WriteLine($"Building KD-routing VP-trees (MaxLeafSeg={MaxLeafSeg}, BucketSize={BucketSize})...");

var rng = new Random(42);

// Reverse dim order map: original dim → reordered index
var revDimOrder = new int[Dims];
for (int i = 0; i < Dims; i++) revDimOrder[dimOrder[i]] = i;

var segIndices = new List<int>[16];
for (int s = 0; s < 16; s++) segIndices[s] = new List<int>(total / 16 + 1);
for (int i = 0; i < total; i++) segIndices[GetSegKey(i)].Add(i);

// Growable sub-seg storage
var segNodeLists       = new List<List<VpNode>>();
var segLeafBlockBytes  = new List<byte[]>();
var segLeafLabelBytes  = new List<byte[]>();
var segLeafBlockCounts = new List<int>();
var segTotalVectors    = new List<int>();
int nextSubSegIdx = 0;

// Per-base routing trees
var baseRouteNodes = new List<RouteNode>[16];
for (int b = 0; b < 16; b++) baseRouteNodes[b] = new List<RouteNode>();

// Mutable state captured by BuildNode; reset per sub-segment.
List<VpNode>  nodes         = null!;
int           leafBlockCount = 0;
MemoryStream  leafBlocksMs   = null!;
MemoryStream  leafLabelsMs   = null!;
BinaryWriter  bwLB           = null!;
BinaryWriter  bwLL           = null!;

for (int b = 0; b < 16; b++)
{
    BuildRouteTree(segIndices[b], baseRouteNodes[b]);
    Console.WriteLine($"  Base {b,2}: {segIndices[b].Count,7} vecs → {baseRouteNodes[b].Count} route nodes, {CountLeaves(baseRouteNodes[b])} sub-segs");
}

int numSubSegs = nextSubSegIdx;
int totalRouteNodes = baseRouteNodes.Sum(r => r.Count);
Console.WriteLine($"KD-routing built: {numSubSegs} sub-segs, {totalRouteNodes} route nodes, " +
                  $"{segNodeLists.Sum(l => l.Count)} VP-nodes, {segLeafBlockCounts.Sum()} leaf blocks");

// Local helpers

int BuildRouteTree(List<int> indices, List<RouteNode> routeNodes)
{
    int nodeIdx = routeNodes.Count;
    routeNodes.Add(default);

    if (indices.Count <= MaxLeafSeg)
    {
        int si = AllocSeg(indices);
        routeNodes[nodeIdx] = new RouteNode { Dim = -1, SegIdx = si };
        return nodeIdx;
    }

    int dim   = FindBestSplitDim(indices);
    int dimR  = revDimOrder[dim];
    short thr = ComputeMedianForDim(indices, dim);

    var lo = new List<int>(indices.Count / 2);
    var hi = new List<int>(indices.Count / 2);
    foreach (var idx in indices)
        (allVecs[idx * 16 + dim] <= thr ? lo : hi).Add(idx);

    if (lo.Count == 0 || hi.Count == 0)
    {
        int si = AllocSeg(indices);
        routeNodes[nodeIdx] = new RouteNode { Dim = -1, SegIdx = si };
        return nodeIdx;
    }

    int loChild = BuildRouteTree(lo, routeNodes);
    int hiChild = BuildRouteTree(hi, routeNodes);
    routeNodes[nodeIdx] = new RouteNode { Dim = dimR, Threshold = (int)thr, LoChild = loChild, HiChild = hiChild, SegIdx = -1 };
    return nodeIdx;
}

int AllocSeg(List<int> indices)
{
    int si = nextSubSegIdx++;
    segNodeLists.Add(null!);
    segLeafBlockBytes.Add(null!);
    segLeafLabelBytes.Add(null!);
    segLeafBlockCounts.Add(0);
    segTotalVectors.Add(0);

    nodes = new List<VpNode>(); leafBlockCount = 0;
    leafBlocksMs = new MemoryStream(); leafLabelsMs = new MemoryStream();
    bwLB = new BinaryWriter(leafBlocksMs); bwLL = new BinaryWriter(leafLabelsMs);
    BuildNode(indices.ToArray());
    bwLB.Flush(); bwLL.Flush();

    segNodeLists[si]       = nodes;
    segLeafBlockBytes[si]  = leafBlocksMs.ToArray();
    segLeafLabelBytes[si]  = leafLabelsMs.ToArray();
    segLeafBlockCounts[si] = leafBlockCount;
    segTotalVectors[si]    = indices.Count;
    return si;
}

int CountLeaves(List<RouteNode> rns) => rns.Count(n => n.Dim == -1);

// Phase 4: write KD-routing vptree.bin (magic "VPTT")
// Layout:
//   [4B]                  magic 0x56505454 "VPTT"
//   [4B]                  numSubSegs
//   [14×4B=56B]           dimOrder
//   [numSubSegs×16B]      per-sub-seg headers [nodeCount, leafBlockCount, totalVectors, 0]
//   [16×4B=64B]           per-base route tree node counts
//   [totalRouteNodes×20B] route tree nodes [dim(reordered), threshold, loChild, hiChild, segIdx]
//   Nodes:      sub-segs 0..N-1, nodeCount[s]×64B each
//   LeafBlocks: sub-segs 0..N-1, leafBlockCount[s]×sizeof(Block)B each
//   LeafLabels: sub-segs 0..N-1, leafBlockCount[s]×16B each
//   FastPath:   appended with magic 0x46415333

using var bw = new BinaryWriter(File.Create(output));
bw.Write(0x56505454); // "VPTT"
bw.Write(numSubSegs);
foreach (var d in dimOrder) bw.Write(d);
for (int s = 0; s < numSubSegs; s++)
{
    bw.Write(segNodeLists[s].Count);
    bw.Write(segLeafBlockCounts[s]);
    bw.Write(segTotalVectors[s]);
    bw.Write(0);
}
for (int b = 0; b < 16; b++) bw.Write(baseRouteNodes[b].Count);
for (int b = 0; b < 16; b++)
    foreach (var rn in baseRouteNodes[b])
    {
        bw.Write(rn.Dim);
        bw.Write(rn.Threshold);
        bw.Write(rn.LoChild);
        bw.Write(rn.HiChild);
        bw.Write(rn.SegIdx);
    }
for (int s = 0; s < numSubSegs; s++) WriteNodes(bw, segNodeLists[s]);
for (int s = 0; s < numSubSegs; s++) bw.Write(segLeafBlockBytes[s]);
for (int s = 0; s < numSubSegs; s++) bw.Write(segLeafLabelBytes[s]);
Console.WriteLine($"Written {output} ({new FileInfo(output).Length / 1024.0 / 1024.0:F1} MiB, {numSubSegs} sub-segs, before fastpath)");

// Phase 5: append profile fast-path table to vptree.bin
Console.WriteLine("Building and appending profile fast-path table...");
BuildFastPath(allVecs, allLabels, total, bw);
bw.Flush();
Console.WriteLine($"Written {output} ({new FileInfo(output).Length / 1024.0 / 1024.0:F1} MiB, with fastpath)");

// Helpers

int GetSegKey(int vecIdx)
{
    int b = vecIdx * 16;
    bool hasLastTx    = allVecs[b + 5] != (short)(-Scale);
    bool isOnline     = allVecs[b + 9] != 0;
    bool cardPresent  = allVecs[b + 10] != 0;
    bool unknownMerch = allVecs[b + 11] != 0;
    return (hasLastTx ? 8 : 0) | (isOnline ? 4 : 0) | (cardPresent ? 2 : 0) | (unknownMerch ? 1 : 0);
}

void WriteNodes(BinaryWriter w, List<VpNode> nodeList)
{
    foreach (var nd in nodeList)
    {
        w.Write(nd.Left);
        w.Write(nd.Right);
        w.Write(nd.Threshold);
        w.Write(nd.VpLabel);
        w.Write((byte)0);          // BlockCountHi (unused)
        w.Write(nd.VpIdxOrCount);
        if (nd.Vp != null)
            foreach (var v in nd.Vp) w.Write(v);
        else
            for (int i = 0; i < Dims; i++) w.Write((short)0);
        for (int i = 0; i < 18; i++) w.Write((byte)0); // pad to 64B
    }
}


int BuildNode(int[] indices)
{
    int nodeIdx = nodes.Count;
    nodes.Add(default);

    if (indices.Length <= BucketSize)
    {
        // Leaf: pack into column-major Block(s) of 8
        int blockStart = leafBlockCount;
        int nBlocks    = (indices.Length + 15) / 16;

        for (int bi = 0; bi < nBlocks; bi++)
        {
            // 14 dims x 16 positions (column-major = Block layout)
            for (int di = 0; di < Dims; di++)
                for (int pos = 0; pos < 16; pos++)
                {
                    int mi = bi * 16 + pos;
                    short v = mi < indices.Length
                        ? allVecs[indices[mi] * 16 + dimOrder[di]]
                        : PaddingSentinel;
                    bwLB.Write(v);
                }
            // Labels for this block's 16 slots
            for (int pos = 0; pos < 16; pos++)
            {
                int mi = bi * 16 + pos;
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
        int nBlocks    = (indices.Length + 15) / 16;
        for (int bi = 0; bi < nBlocks; bi++)
        {
            for (int di = 0; di < Dims; di++)
                for (int pos = 0; pos < 16; pos++)
                {
                    int mi = bi * 16 + pos;
                    short v = mi < indices.Length
                        ? allVecs[indices[mi] * 16 + dimOrder[di]]
                        : PaddingSentinel;
                    bwLB.Write(v);
                }
            for (int pos = 0; pos < 16; pos++)
            {
                int mi = bi * 16 + pos;
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

// Shared helpers

int FindBestSplitDim(List<int> indices)
{
    double bestVar = -1; int bestDim = 0;
    for (int d = 0; d < Dims; d++)
    {
        if (d is 9 or 10 or 11) continue; // skip binary seg-key dims (5,6 have real values in segs 8-15)
        double sum = 0, sum2 = 0, n = indices.Count;
        foreach (var idx in indices) { double v = allVecs[idx * 16 + d]; sum += v; sum2 += v * v; }
        double variance = sum2 / n - (sum / n) * (sum / n);
        if (variance > bestVar) { bestVar = variance; bestDim = d; }
    }
    return bestDim;
}

short ComputeMedianForDim(List<int> indices, int dim)
{
    var vals = indices.Select(idx => allVecs[idx * 16 + dim]).ToArray();
    Array.Sort(vals);
    return vals[vals.Length / 2];
}

static short Quantize(double v)
{
    var q = (int)Math.Round(v * Scale);
    if (q > short.MaxValue) q = short.MaxValue;
    if (q < short.MinValue) q = short.MinValue;
    return (short)q;
}

static void BuildFastPath(short[] allVecs, byte[] allLabels, int total, BinaryWriter bw)
{
    int[] featureIndex = [6,  2,  5, 0, 12, 7, 9, 10, 11];
    int[] bits         = [6,  4,  3, 3,  2, 2, 1,  1,  1]; // sum=23 => 8M entries x 2B = 16 MiB

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

    bw.Write(unchecked((int)0x46415333));
    for (int f = 0; f < nf; f++)
    {
        bw.Write(edges[f].Length);
        foreach (var e in edges[f]) bw.Write(e);
    }
    bw.Write(tableSize);
    foreach (var v in table) bw.Write(v);
}

static int FindBinS(short[] edges, short v)
{
    for (int b = 0; b < edges.Length; b++)
        if (v < edges[b]) return b;
    return edges.Length;
}

struct RouteNode
{
    public int Dim;       // reordered dim index (-1 = leaf)
    public int Threshold; // int16 value stored as int
    public int LoChild;   // index in this base seg's route tree (-1 if leaf)
    public int HiChild;
    public int SegIdx;    // global sub-seg index (leaves only, -1 for internal)
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
