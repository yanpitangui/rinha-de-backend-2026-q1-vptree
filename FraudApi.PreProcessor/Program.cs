using System.IO.Compression;
using System.Text.Json;
using FraudApi.Shared;

const int Scale = 10000;
const int BlockSize = 8;
const int Dims = 14;
const int K = 1280;
const int KMeansIter = 25;
const int SampleSize = 262144;
const short PaddingSentinel = Scale; // > any valid value, keeps padded slots far from queries
const int Magic = unchecked((int)0x32465649); // "IVF2"

var resourcesPath =
    args.Length > 0
        ? args[0]
        : Environment.GetEnvironmentVariable("RESOURCES_PATH")
        ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var input = Path.Combine(resourcesPath, "references.json.gz");
var output = Path.Combine(resourcesPath, "dataset.bin");

Console.WriteLine($"Loading dataset from: {input}");

// ── Phase 1: stream all vectors into flat row-major arrays ────────────────
const int MaxVectors = 3_100_000;
var allVecs   = new short[MaxVectors * 16]; // row-major: allVecs[i*16+d]
var allLabels = new byte[MaxVectors];
int total = 0;

{
    using var fs  = File.OpenRead(input);
    using var gz  = new GZipStream(fs, CompressionMode.Decompress);

    byte[] buffer = new byte[64 * 1024];
    int bytesInBuffer = 0;
    var state = new JsonReaderState();

    double[] vec = new double[Dims];
    bool inVector = false;
    int vi = 0;
    bool isFraud = false;
    bool vecComplete = false;

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
                inVector = false;
                vecComplete = true;
                break;
            case JsonTokenType.EndObject when vecComplete:
                int @base = total * 16;
                for (int d = 0; d < Dims; d++)
                    allVecs[@base + d] = Quantize(vec[d]);
                allLabels[total] = isFraud ? (byte)1 : (byte)0;
                total++;
                vecComplete = false;
                isFraud = false;
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

// ── Phase 2: compute per-dim variance using Welford's online algorithm ─────
// High-variance dims are checked first in ProcessAllDims for maximum early-exit pruning.
var mean = new double[Dims];
var m2   = new double[Dims];
for (int i = 0; i < total; i++)
{
    int vb = i * 16;
    for (int d = 0; d < Dims; d++)
    {
        double x = allVecs[vb + d];
        double delta = x - mean[d];
        mean[d] += delta / (i + 1);
        m2[d] += delta * (x - mean[d]);
    }
}
var dimVariance = new double[Dims];
for (int d = 0; d < Dims; d++) dimVariance[d] = m2[d] / total;

var dimOrder = Enumerable.Range(0, Dims).OrderByDescending(d => dimVariance[d]).ToArray();
Console.WriteLine($"Dim order (high→low variance): [{string.Join(", ", dimOrder)}]");
for (int i = 0; i < Dims; i++)
    Console.WriteLine($"  dim[{dimOrder[i],2}] variance={dimVariance[dimOrder[i]]:F2}");

// ── Phase 3: k-means++ on a sample ───────────────────────────────────────
Console.WriteLine($"Running k-means (K={K})...");
var rng = new Random(42);
var sampleIdx = ReservoirSample(total, SampleSize, rng);
var centroids = RunKMeans(allVecs, sampleIdx, K, KMeansIter, "mixed", rng);

// ── Phase 4: assign all vectors to clusters ───────────────────────────────
Console.WriteLine("Assigning all vectors to clusters...");
var assignments = new int[total];
Parallel.For(0, total, i =>
    assignments[i] = NearestCentroidInRange(allVecs, i * 16, centroids, 0, K));

// ── Phase 5: group by cluster ─────────────────────────────────────────────
var clusterMembers = new List<int>[K];
for (int k = 0; k < K; k++) clusterMembers[k] = new List<int>(total / K + BlockSize);
for (int i = 0; i < total; i++) clusterMembers[assignments[i]].Add(i);

// ── Phase 6: write binary ─────────────────────────────────────────────────
Console.WriteLine("Writing dataset.bin...");

var clusterBlockStart = new int[K];
var clusterBlockLen   = new int[K];
int blockCount = 0;
for (int k = 0; k < K; k++)
{
    clusterBlockStart[k] = blockCount;
    int numBlocks = (clusterMembers[k].Count + BlockSize - 1) / BlockSize;
    if (numBlocks == 0) numBlocks = 1;
    clusterBlockLen[k] = numBlocks;
    blockCount += numBlocks;
}

var bboxMin = new short[K * Dims];
var bboxMax = new short[K * Dims];
Array.Fill(bboxMin, short.MaxValue);
Array.Fill(bboxMax, short.MinValue);
for (int k = 0; k < K; k++)
{
    var members = clusterMembers[k];
    if (members.Count == 0)
    {
        Array.Fill(bboxMin, (short)0, k * Dims, Dims);
        Array.Fill(bboxMax, (short)0, k * Dims, Dims);
        continue;
    }
    for (int di = 0; di < Dims; di++)
    {
        int d = dimOrder[di];
        short mn = short.MaxValue, mx = short.MinValue;
        foreach (int idx in members) { short v = allVecs[idx * 16 + d]; if (v < mn) mn = v; if (v > mx) mx = v; }
        bboxMin[k * Dims + di] = mn;
        bboxMax[k * Dims + di] = mx;
    }
}

using var bw = new BinaryWriter(File.Create(output));

// Header
bw.Write(Magic);
bw.Write(blockCount);
bw.Write(total);
bw.Write(K);

// DimOrder (14 ints) — must match MmapData.cs offset 16
foreach (var d in dimOrder) bw.Write(d);

// Centroids (K * 16 floats)
for (int i = 0; i < K * 16; i++) bw.Write(centroids[i]);

// Cluster metadata
for (int k = 0; k < K; k++) bw.Write(clusterBlockStart[k]);
for (int k = 0; k < K; k++) bw.Write(clusterBlockLen[k]);

// Bounding boxes (K * Dims shorts each)
foreach (var v in bboxMin) bw.Write(v);
foreach (var v in bboxMax) bw.Write(v);

// Blocks (ordered by cluster)
for (int k = 0; k < K; k++)
{
    var members = clusterMembers[k];
    int numBlocks = clusterBlockLen[k];
    for (int bi = 0; bi < numBlocks; bi++)
        WriteBlock(bw, allVecs, members, bi * BlockSize, Math.Min(BlockSize, members.Count - bi * BlockSize), dimOrder);
}

// Labels (ordered by cluster, padded with 0)
for (int k = 0; k < K; k++)
{
    var members = clusterMembers[k];
    int numBlocks = clusterBlockLen[k];
    for (int bi = 0; bi < numBlocks; bi++)
        for (int pos = 0; pos < BlockSize; pos++)
        {
            int memberPos = bi * BlockSize + pos;
            bw.Write(memberPos < members.Count ? allLabels[members[memberPos]] : (byte)0);
        }
}

Console.WriteLine($"Done. total={total}, K={K}, blockCount={blockCount}");

// ── Phase 7: build profile fast-path table ────────────────────────────────
Console.WriteLine("Building profile fast-path table...");
BuildFastPath(allVecs, allLabels, total, resourcesPath);

// ── Helpers ───────────────────────────────────────────────────────────────

static short Quantize(double v)
{
    var q = (int)Math.Round(v * Scale);
    if (q > short.MaxValue) q = short.MaxValue;
    if (q < short.MinValue) q = short.MinValue;
    return (short)q;
}

static int[] ReservoirSample(int n, int s, Random rng)
{
    var result = new int[s];
    for (int i = 0; i < s && i < n; i++) result[i] = i;
    for (int i = s; i < n; i++)
    {
        int j = rng.Next(i + 1);
        if (j < s) result[j] = i;
    }
    return result;
}

static float[] KMeansPlusPlusInit(short[] vecs, int[] sample, int k, Random rng)
{
    var centroids = new float[k * 16];
    int first = sample[rng.Next(sample.Length)] * 16;
    for (int d = 0; d < Dims; d++) centroids[d] = vecs[first + d];

    var minDist = new float[sample.Length];
    minDist.AsSpan().Fill(float.MaxValue);

    for (int ci = 1; ci < k; ci++)
    {
        int prevCBase = (ci - 1) * 16;
        Parallel.For(0, sample.Length, si =>
        {
            float d = CentroidDist(vecs, sample[si] * 16, centroids, prevCBase);
            if (d < minDist[si]) minDist[si] = d;
        });
        float total = 0;
        for (int si = 0; si < sample.Length; si++) total += minDist[si];
        float threshold = (float)(rng.NextDouble() * total);
        float cum = 0;
        int chosen = sample.Length - 1;
        for (int si = 0; si < sample.Length; si++)
        {
            cum += minDist[si];
            if (cum >= threshold) { chosen = si; break; }
        }
        int vb = sample[chosen] * 16;
        int cb = ci * 16;
        for (int d = 0; d < Dims; d++) centroids[cb + d] = vecs[vb + d];
    }
    return centroids;
}

static float CentroidDist(short[] vecs, int vBase, float[] centroids, int cBase)
{
    float dist = 0;
    for (int d = 0; d < Dims; d++)
    {
        float diff = vecs[vBase + d] - centroids[cBase + d];
        dist += diff * diff;
    }
    return dist;
}

static int NearestCentroidInRange(short[] vecs, int vBase, float[] centroids, int start, int count)
{
    int best = 0;
    float bestDist = float.MaxValue;
    for (int i = 0; i < count; i++)
    {
        float dist = CentroidDist(vecs, vBase, centroids, (start + i) * 16);
        if (dist < bestDist) { bestDist = dist; best = i; }
    }
    return best;
}

static float[] RunKMeans(short[] vecs, int[] sampleIdx, int k, int iters, string label, Random rng)
{
    Console.WriteLine($"  K-means {label}: k={k}, sample={sampleIdx.Length}");
    var centroids = KMeansPlusPlusInit(vecs, sampleIdx, k, rng);
    var tempAssign = new int[sampleIdx.Length];
    var newCentroids = new float[k * 16];
    var counts = new int[k];

    for (int iter = 0; iter < iters; iter++)
    {
        Parallel.For(0, sampleIdx.Length, si =>
            tempAssign[si] = NearestCentroidInRange(vecs, sampleIdx[si] * 16, centroids, 0, k));

        Array.Clear(newCentroids);
        Array.Clear(counts);
        for (int si = 0; si < sampleIdx.Length; si++)
        {
            int ck = tempAssign[si];
            int vb = sampleIdx[si] * 16;
            for (int d = 0; d < Dims; d++)
                newCentroids[ck * 16 + d] += vecs[vb + d];
            counts[ck]++;
        }

        for (int ck = 0; ck < k; ck++)
        {
            if (counts[ck] == 0) continue;
            for (int d = 0; d < Dims; d++)
                newCentroids[ck * 16 + d] /= counts[ck];
        }
        for (int ck = 0; ck < k; ck++)
        {
            if (counts[ck] == 0)
            {
                int fallback = sampleIdx[rng.Next(sampleIdx.Length)] * 16;
                for (int d = 0; d < Dims; d++)
                    newCentroids[ck * 16 + d] = vecs[fallback + d];
            }
        }
        Array.Copy(newCentroids, centroids, k * 16);
        if ((iter + 1) % 5 == 0) Console.WriteLine($"    {label} iter {iter+1}/{iters}");
    }
    return centroids;
}

static void BuildFastPath(short[] allVecs, byte[] allLabels, int total, string resourcesPath)
{
    // 22-bit key: booleans get 1 bit, continuous features get proportional bits.
    // MUST stay in sync with FraudApi/FraudDetection/ProfileFastPath.cs constants.
    int[] featureIndex = [0, 12,  2, 7, 8, 1, 9, 10, 11];
    int[] bits         = [5,  4,  3, 3, 2, 2, 1,  1,  1]; // sum=22 → 4M entries × 4 bytes = 16 MiB

    int nf = featureIndex.Length;
    int tableSize = 1 << bits.Sum();

    var shifts = new int[nf];
    for (int f = 1; f < nf; f++) shifts[f] = shifts[f - 1] + bits[f - 1];

    // Quantile edges per feature (int16 space)
    var edges = new short[nf][];
    for (int f = 0; f < nf; f++)
    {
        int dim = featureIndex[f];
        int numBins  = 1 << bits[f];
        int numEdges = numBins - 1;

        var values = new short[total];
        for (int i = 0; i < total; i++) values[i] = allVecs[i * 16 + dim];
        Array.Sort(values);

        edges[f] = new short[numEdges];
        for (int b = 0; b < numEdges; b++)
        {
            int pos = (int)((long)(b + 1) * total / numBins);
            edges[f][b] = values[pos];
        }
    }

    // Count total and fraud per bucket.
    // Packed ulong: upper 32 = total_count, lower 32 = fraud_count.
    var buckets = new Dictionary<uint, ulong>(1 << 20);
    for (int i = 0; i < total; i++)
    {
        uint key = 0;
        for (int f = 0; f < nf; f++)
            key |= (uint)FindBinS(edges[f], allVecs[i * 16 + featureIndex[f]]) << shifts[f];

        ulong cur = buckets.TryGetValue(key, out var c) ? c : 0UL;
        ulong fraudInc = allLabels[i]; // 1 if fraud, 0 if legit
        buckets[key] = cur + (1UL << 32) + fraudInc;
    }

    // Build dense uint table: entry = (total << 16) | fraud, both capped at 65535.
    // Thresholds are applied at runtime (env vars); we store raw counts here.
    var table = new uint[tableSize];
    foreach (var kv in buckets)
    {
        long totalL = (long)(kv.Value >> 32);
        long fraudL = (long)(kv.Value & 0xFFFFFFFF);
        uint packed = ((uint)Math.Min(totalL, 65535) << 16) | (uint)Math.Min(fraudL, 65535);
        table[kv.Key] = packed;
    }

    // Log estimated hit rate using default runtime thresholds for reference.
    const int defPureLegitMin = 5, defPureFraudMin = 10, defDomMin = 50;
    long hitsPureLegit = 0, hitsPureFraud = 0, hitsDom = 0;
    foreach (var kv in buckets)
    {
        long totalL = (long)(kv.Value >> 32);
        long fraudL = (long)(kv.Value & 0xFFFFFFFF);
        long legitL = totalL - fraudL;
        if (fraudL == 0 && totalL >= defPureLegitMin)  hitsPureLegit += totalL;
        else if (legitL == 0 && totalL >= defPureFraudMin) hitsPureFraud += totalL;
        else if ((fraudL <= 1 || legitL <= 1) && totalL >= defDomMin) hitsDom += totalL;
    }
    long totalHits = hitsPureLegit + hitsPureFraud + hitsDom;
    Console.WriteLine($"  Fast-path coverage (default thresholds): {totalHits * 100.0 / total:F1}%  " +
                      $"(pure-legit={hitsPureLegit}, pure-fraud={hitsPureFraud}, dominant={hitsDom})");

    // Write fastpath.bin — magic 0x46415332 ("FAS2"), edges, then uint table.
    var outputPath = Path.Combine(resourcesPath, "fastpath.bin");
    using var bw2 = new BinaryWriter(File.Create(outputPath));
    bw2.Write(unchecked((int)0x46415332)); // "FAS2"
    for (int f = 0; f < nf; f++)
    {
        bw2.Write(edges[f].Length);
        foreach (var e in edges[f]) bw2.Write(e);
    }
    bw2.Write(tableSize);
    foreach (var v in table) bw2.Write(v);
    Console.WriteLine($"  Written {outputPath} ({new FileInfo(outputPath).Length / 1024 / 1024} MiB)");
}

static int FindBinS(short[] edges, short v)
{
    for (int b = 0; b < edges.Length; b++)
        if (v < edges[b]) return b;
    return edges.Length;
}

static unsafe void WriteBlock(BinaryWriter bw, short[] vecs, List<int> members, int start, int realCount, int[] dimOrder)
{
    Block b = default;
    short* ptr = (short*)&b;
    for (int pos = 0; pos < BlockSize; pos++)
    {
        int memberPos = start + pos;
        int vb = memberPos < members.Count ? members[memberPos] * 16 : -1;
        for (int di = 0; di < Dims; di++)
            ptr[di * BlockSize + pos] = vb >= 0 ? vecs[vb + dimOrder[di]] : PaddingSentinel;
    }
    bw.Write(new ReadOnlySpan<byte>(ptr, sizeof(Block)));
}
