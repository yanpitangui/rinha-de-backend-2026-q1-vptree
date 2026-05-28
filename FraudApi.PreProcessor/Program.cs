using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text.Json;
using FraudApi.Shared;

const int   Scale           = 10000;
const int   Dims            = 14;
int         BucketSize      = int.TryParse(Environment.GetEnvironmentVariable("BUCKET_SIZE"), out var bs) ? bs : 1024;
int         VpSampleSize    = int.TryParse(Environment.GetEnvironmentVariable("VP_SAMPLE_SIZE"), out var vps) ? vps : 20;
const short PaddingSentinel = short.MaxValue;

var resourcesPath =
    args.Length > 0
        ? args[0]
        : Environment.GetEnvironmentVariable("RESOURCES_PATH")
        ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var input  = Path.Combine(resourcesPath, "references.json.gz");
var output = Path.Combine(resourcesPath, "vptree.bin");

Console.WriteLine($"Loading dataset from: {input}");

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

Console.WriteLine($"Loaded {total} vectors. Computing dim variance and partition thresholds...");

// Phase 2: per-dim variance → dimOrder + equifreq thresholds for 256-partition key
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

// Compute equifreq median thresholds for dims 8 and 2, and quartile thresholds for dim 0.
// Used to build 8-bit partition key: existing 4 binary bits + 2 median bits + 2-bit amount bucket.
short Median(int dim)
{
    var vals = new short[total];
    for (int i = 0; i < total; i++) vals[i] = allVecs[i * 16 + dim];
    Array.Sort(vals);
    return vals[total / 2];
}
short dim8Thresh = Median(8);
short dim2Thresh = Median(2);
short[] dim0Thresholds = new short[3]; // Q1, Q2, Q3 → 4 buckets
{
    var vals = new short[total];
    for (int i = 0; i < total; i++) vals[i] = allVecs[i * 16 + 0];
    Array.Sort(vals);
    for (int q = 0; q < 3; q++) dim0Thresholds[q] = vals[(q + 1) * total / 4];
}
Console.WriteLine($"Partition thresholds: dim8={dim8Thresh}, dim2={dim2Thresh}, dim0=[{string.Join(",", dim0Thresholds)}]");

// Phase 3: KD-routing VP-tree with 256 partitions + bounding boxes.
// Partition key: 8 bits = 4 binary dims + dim8 median + dim2 median + dim0 2-bit bucket.
// Magic 0x56505442 "VPTB".
const int NumBaseParts = 256;
int MaxLeafSeg = int.TryParse(Environment.GetEnvironmentVariable("MAX_LEAF_SEG"), out var ml) ? ml : 512;
Console.WriteLine($"Building VPTB (256-partition + bounding-box, MaxLeafSeg={MaxLeafSeg}, BucketSize={BucketSize})...");

var rng = new Random(42);

var revDimOrder = new int[Dims];
for (int i = 0; i < Dims; i++) revDimOrder[dimOrder[i]] = i;

var segIndices = new List<int>[NumBaseParts];
for (int s = 0; s < NumBaseParts; s++) segIndices[s] = new List<int>(total / NumBaseParts + 1);
for (int i = 0; i < total; i++) segIndices[GetSegKey(i)].Add(i);

var segNodeLists       = new List<List<VpNode>>();
var segLeafBlockBytes  = new List<byte[]>();
var segLeafLabelBytes  = new List<byte[]>();
var segLeafBlockCounts = new List<int>();
var segTotalVectors    = new List<int>();
int nextSubSegIdx = 0;

var baseRouteNodes = new List<RouteNode>[NumBaseParts];
for (int b = 0; b < NumBaseParts; b++) baseRouteNodes[b] = new List<RouteNode>();

List<VpNode>  nodes        = null!;
int           leafBlockCount = 0;
MemoryStream  leafBlocksMs   = null!;
MemoryStream  leafLabelsMs   = null!;
BinaryWriter  bwLB           = null!;
BinaryWriter  bwLL           = null!;

for (int b = 0; b < NumBaseParts; b++)
{
    if (segIndices[b].Count == 0)
    {
        // Never-visit box: min=MaxValue, max=MinValue → box lower bound is huge.
        var emptyMin = new short[16]; var emptyMax = new short[16];
        for (int d = 0; d < 16; d++) { emptyMin[d] = short.MaxValue; emptyMax[d] = short.MinValue; }
        baseRouteNodes[b].Add(new RouteNode { Dim = -1, SegIdx = -1, BoxMin = emptyMin, BoxMax = emptyMax });
        continue;
    }
    BuildRouteTree(segIndices[b], baseRouteNodes[b]);
}

// Per-partition bounding boxes (in reordered dim space, 16 shorts each for aligned loads).
var bbMins = new short[NumBaseParts * 16];
var bbMaxs = new short[NumBaseParts * 16];
for (int b = 0; b < NumBaseParts; b++)
{
    for (int d = 0; d < 16; d++) { bbMins[b * 16 + d] = short.MaxValue; bbMaxs[b * 16 + d] = short.MinValue; }
    foreach (int idx in segIndices[b])
    {
        int vb = idx * 16;
        for (int d = 0; d < Dims; d++)
        {
            short v = allVecs[vb + dimOrder[d]]; // reordered
            if (v < bbMins[b * 16 + d]) bbMins[b * 16 + d] = v;
            if (v > bbMaxs[b * 16 + d]) bbMaxs[b * 16 + d] = v;
        }
    }
}

int numSubSegs      = nextSubSegIdx;
int totalRouteNodes = baseRouteNodes.Sum(r => r.Count);
Console.WriteLine($"VPTB built: {numSubSegs} sub-segs, {totalRouteNodes} route nodes, " +
                  $"{segNodeLists.Sum(l => l.Count)} VP-nodes, {segLeafBlockCounts.Sum()} leaf blocks");

// Phase 4: write VPTB format.
// [4B] magic 0x56505442 "VPTB"
// [4B] numSubSegs
// [14×4B=56B] dimOrder
// [4B] numBaseParts = 256
// [numSubSegs×16B] per-sub-seg headers [nodeCount, leafBlockCount, totalVectors, 0]
// [256×4B=1KB] per-base route node counts
// [totalRouteNodes×20B] route tree nodes
// [totalRouteNodes×32×2B] route node boxes: per node 16 min shorts + 16 max shorts (reordered space)
// [3×2B=6B] partition thresholds: dim8Thresh, dim2Thresh, dim0Q1, dim0Q2, dim0Q3 (+ 1B pad to even)
// [256×16×2B×2 = 16KB] bounding boxes: all mins then all maxs (16 shorts each, 2 padding dims)
// Nodes, LeafBlocks, LeafLabels, FastPath
using var bw = new BinaryWriter(File.Create(output));
bw.Write(0x56505442); // "VPTB"
bw.Write(numSubSegs);
foreach (var d in dimOrder) bw.Write(d);
bw.Write(NumBaseParts);
for (int s = 0; s < numSubSegs; s++)
{
    bw.Write(segNodeLists[s].Count);
    bw.Write(segLeafBlockCounts[s]);
    bw.Write(segTotalVectors[s]);
    bw.Write(0);
}
for (int b = 0; b < NumBaseParts; b++) bw.Write(baseRouteNodes[b].Count);
for (int b = 0; b < NumBaseParts; b++)
    foreach (var rn in baseRouteNodes[b])
    {
        bw.Write(rn.Dim); bw.Write(rn.Threshold);
        bw.Write(rn.LoChild); bw.Write(rn.HiChild); bw.Write(rn.SegIdx);
    }
// Route node boxes: per node 16 min shorts then 16 max shorts (reordered space)
for (int b = 0; b < NumBaseParts; b++)
    foreach (var rn in baseRouteNodes[b])
    {
        for (int d = 0; d < 16; d++) bw.Write(rn.BoxMin[d]);
        for (int d = 0; d < 16; d++) bw.Write(rn.BoxMax[d]);
    }
// Partition thresholds (5 shorts + 1 pad short = 12B)
bw.Write(dim8Thresh); bw.Write(dim2Thresh);
bw.Write(dim0Thresholds[0]); bw.Write(dim0Thresholds[1]); bw.Write(dim0Thresholds[2]);
bw.Write((short)0); // pad to even
// Bounding boxes: all 256 mins then all 256 maxs (each 16 shorts)
for (int b = 0; b < NumBaseParts; b++)
    for (int d = 0; d < 16; d++) bw.Write(bbMins[b * 16 + d]);
for (int b = 0; b < NumBaseParts; b++)
    for (int d = 0; d < 16; d++) bw.Write(bbMaxs[b * 16 + d]);
for (int s = 0; s < numSubSegs; s++) WriteNodes(bw, segNodeLists[s]);
for (int s = 0; s < numSubSegs; s++) bw.Write(segLeafBlockBytes[s]);
for (int s = 0; s < numSubSegs; s++) bw.Write(segLeafLabelBytes[s]);
Console.WriteLine($"Written {output} ({new FileInfo(output).Length / 1024.0 / 1024.0:F1} MiB, {numSubSegs} sub-segs, before fastpath)");

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
    int  txCountBit   = allVecs[b + 8] > dim8Thresh ? 1 : 0;
    int  amtVsAvgBit  = allVecs[b + 2] > dim2Thresh ? 1 : 0;
    int  amtBucket    = GetDim0Bucket(allVecs[b + 0]);
    return (hasLastTx ? 8 : 0) | (isOnline ? 4 : 0) | (cardPresent ? 2 : 0) | (unknownMerch ? 1 : 0)
         | (txCountBit << 4) | (amtVsAvgBit << 5) | (amtBucket << 6);
}

int GetDim0Bucket(short v)
{
    if (v <= dim0Thresholds[0]) return 0;
    if (v <= dim0Thresholds[1]) return 1;
    if (v <= dim0Thresholds[2]) return 2;
    return 3;
}

int BuildRouteTree(List<int> indices, List<RouteNode> routeNodes)
{
    int nodeIdx = routeNodes.Count;
    routeNodes.Add(default);

    ComputeReorderedBox(indices, out var boxMin, out var boxMax);

    if (indices.Count <= MaxLeafSeg)
    {
        int si = AllocSeg(indices);
        routeNodes[nodeIdx] = new RouteNode { Dim = -1, SegIdx = si, BoxMin = boxMin, BoxMax = boxMax };
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
        routeNodes[nodeIdx] = new RouteNode { Dim = -1, SegIdx = si, BoxMin = boxMin, BoxMax = boxMax };
        return nodeIdx;
    }

    int loChild = BuildRouteTree(lo, routeNodes);
    int hiChild = BuildRouteTree(hi, routeNodes);
    routeNodes[nodeIdx] = new RouteNode { Dim = dimR, Threshold = (int)thr, LoChild = loChild, HiChild = hiChild, SegIdx = -1, BoxMin = boxMin, BoxMax = boxMax };
    return nodeIdx;
}

void ComputeReorderedBox(List<int> indices, out short[] boxMin, out short[] boxMax)
{
    boxMin = new short[16];
    boxMax = new short[16];
    for (int d = 0; d < 16; d++) { boxMin[d] = short.MaxValue; boxMax[d] = short.MinValue; }
    foreach (int idx in indices)
    {
        int vb = idx * 16;
        for (int d = 0; d < Dims; d++)
        {
            short v = allVecs[vb + dimOrder[d]]; // reordered
            if (v < boxMin[d]) boxMin[d] = v;
            if (v > boxMax[d]) boxMax[d] = v;
        }
    }
    // Pad dims 14,15 → 0 so they never contribute to box lower bound.
    boxMin[14] = 0; boxMin[15] = 0; boxMax[14] = 0; boxMax[15] = 0;
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

void WriteNodes(BinaryWriter w, List<VpNode> nodeList)
{
    foreach (var nd in nodeList)
    {
        w.Write(nd.Left); w.Write(nd.Right); w.Write(nd.Threshold);
        w.Write(nd.VpLabel); w.Write((byte)0); w.Write(nd.VpIdxOrCount);
        if (nd.Vp != null) foreach (var v in nd.Vp) w.Write(v);
        else for (int i = 0; i < Dims; i++) w.Write((short)0);
        for (int i = 0; i < 18; i++) w.Write((byte)0);
    }
}

int BuildNode(int[] indices)
{
    int nodeIdx = nodes.Count;
    nodes.Add(default);

    if (indices.Length <= BucketSize)
    {
        int blockStart = leafBlockCount;
        int nBlocks    = (indices.Length + 15) / 16;
        for (int bi = 0; bi < nBlocks; bi++)
        {
            for (int di = 0; di < Dims; di++)
                for (int pos = 0; pos < 16; pos++)
                {
                    int mi = bi * 16 + pos;
                    short v = mi < indices.Length ? allVecs[indices[mi] * 16 + dimOrder[di]] : PaddingSentinel;
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

    int vpGlobalIdx = PickVantagePoint(indices);
    int nonVpCount = indices.Length - 1;
    var distPairs  = new (int idx, long dsq)[nonVpCount];
    int di2 = 0;
    foreach (var idx in indices)
        if (idx != vpGlobalIdx) distPairs[di2++] = (idx, DistSqInt64(idx, vpGlobalIdx));
    Array.Sort(distPairs, (a, b) => a.dsq.CompareTo(b.dsq));

    int mid = Math.Max(1, nonVpCount / 2);
    if (mid >= nonVpCount)
    {
        int blockStart = leafBlockCount;
        int nBlocks    = (indices.Length + 15) / 16;
        for (int bi = 0; bi < nBlocks; bi++)
        {
            for (int di = 0; di < Dims; di++)
                for (int pos = 0; pos < 16; pos++)
                {
                    int mi = bi * 16 + pos;
                    short v = mi < indices.Length ? allVecs[indices[mi] * 16 + dimOrder[di]] : PaddingSentinel;
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

    float mu = MathF.Sqrt((float)distPairs[mid - 1].dsq); // raw linear int distance (integer currency)
    var leftArr  = new int[mid];
    var rightArr = new int[nonVpCount - mid];
    for (int i = 0; i < mid; i++)        leftArr[i]        = distPairs[i].idx;
    for (int i = mid; i < nonVpCount; i++) rightArr[i - mid] = distPairs[i].idx;

    int leftChild  = BuildNode(leftArr);
    int rightChild = BuildNode(rightArr);

    var vp = new short[Dims];
    for (int di = 0; di < Dims; di++) vp[di] = allVecs[vpGlobalIdx * 16 + dimOrder[di]];

    nodes[nodeIdx] = new VpNode { Left = leftChild, Right = rightChild, Threshold = mu, VpLabel = allLabels[vpGlobalIdx], VpIdxOrCount = 0, Vp = vp };
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
    int bestVp = sample[0]; long bestSum = long.MinValue;
    for (int i = 0; i < sampleSize; i++)
    {
        long sum = 0;
        for (int j = 0; j < sampleSize; j++) if (i != j) sum += DistSqInt64(sample[i], sample[j]);
        if (sum > bestSum) { bestSum = sum; bestVp = sample[i]; }
    }
    return bestVp;
}

long DistSqInt64(int aIdx, int bIdx)
{
    long acc = 0;
    int ab = aIdx * 16, bb = bIdx * 16;
    for (int d = 0; d < Dims; d++) { int diff = allVecs[ab + d] - allVecs[bb + d]; acc += diff * diff; }
    return acc;
}

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
    int[] bits         = [6,  4,  3, 3,  2, 2, 1,  1,  1];

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

    const int defPureLegitMin = 100, defPureFraudMin = 20, defDomFraudMin = 100;
    long hitsPureLegit = 0, hitsPureFraud = 0, hitsDom = 0;
    foreach (var kv in buckets)
    {
        long totalL = (long)(kv.Value >> 32);
        long fraudL = (long)(kv.Value & 0xFFFFFFFF);
        long legitL = totalL - fraudL;
        if (fraudL == 0 && totalL >= defPureLegitMin)     hitsPureLegit += totalL;
        else if (legitL == 0 && totalL >= defPureFraudMin) hitsPureFraud += totalL;
        else if (legitL == 1 && totalL >= defDomFraudMin)  hitsDom       += totalL;
    }
    Console.WriteLine($"  Fast-path coverage: {(hitsPureLegit+hitsPureFraud+hitsDom)*100.0/total:F1}%");

    bw.Write(unchecked((int)0x46415333));
    for (int f = 0; f < nf; f++) { bw.Write(edges[f].Length); foreach (var e in edges[f]) bw.Write(e); }
    bw.Write(tableSize);
    foreach (var v in table) bw.Write(v);
}

static int FindBinS(short[] edges, short v)
{
    for (int b = 0; b < edges.Length; b++) if (v < edges[b]) return b;
    return edges.Length;
}

struct RouteNode
{
    public int Dim;
    public int Threshold;
    public int LoChild;
    public int HiChild;
    public int SegIdx;
    public short[] BoxMin; // 16 shorts, reordered dim space (14 real + 2 pad)
    public short[] BoxMax;
}

[StructLayout(LayoutKind.Sequential)]
struct VpNode
{
    public int    Left;
    public int    Right;
    public float  Threshold;
    public byte   VpLabel;
    public int    VpIdxOrCount;
    public short[]? Vp;
}
