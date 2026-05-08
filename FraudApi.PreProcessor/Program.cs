using System.IO.Compression;
using System.Text.Json;
using FraudApi.Shared;

const int Scale = 8192;
const int BlockSize = 64;
const int Dims = 14;
const int K = 4096;
const int KMeansIter = 25;
const int SampleSize = 262144;
const short PaddingSentinel = 8192;
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

    void ProcessToken2(ref Utf8JsonReader r)
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
        while (reader.Read()) ProcessToken2(ref reader);

        int consumed = (int)reader.BytesConsumed;
        Buffer.BlockCopy(buffer, consumed, buffer, 0, bytesInBuffer - consumed);
        bytesInBuffer -= consumed;
        state = reader.CurrentState;
    }

    var finalReader = new Utf8JsonReader(new ReadOnlySpan<byte>(buffer, 0, bytesInBuffer), true, state);
    while (finalReader.Read()) ProcessToken2(ref finalReader);
}

Console.WriteLine($"Loaded {total} vectors. Running k-means (K={K})...");

// ── Phase 2: k-means++ on a sample ───────────────────────────────────────
var rng = new Random(42);
var sampleIdx = ReservoirSample(total, SampleSize, rng);
var centroids = RunKMeans(allVecs, sampleIdx, K, KMeansIter, "mixed", rng);

// ── Phase 3: assign all vectors to clusters ───────────────────────────────
Console.WriteLine("Assigning all vectors to clusters...");
var assignments = new int[total];
Parallel.For(0, total, i =>
    assignments[i] = NearestCentroidInRange(allVecs, i * 16, centroids, 0, K));

// ── Phase 4: group by cluster ─────────────────────────────────────────────
var clusterMembers = new List<int>[K];
for (int k = 0; k < K; k++) clusterMembers[k] = new List<int>(total / K + 64);
for (int i = 0; i < total; i++) clusterMembers[assignments[i]].Add(i);

// ── Phase 5: write binary ─────────────────────────────────────────────────
Console.WriteLine("Writing dataset.bin...");

// Compute block counts per cluster (pad to multiple of BlockSize)
var clusterBlockStart = new int[K];
var clusterBlockLen   = new int[K];
int blockCount = 0;
for (int k = 0; k < K; k++)
{
    clusterBlockStart[k] = blockCount;
    int numBlocks = (clusterMembers[k].Count + BlockSize - 1) / BlockSize;
    if (numBlocks == 0) numBlocks = 1; // empty cluster still gets one block
    clusterBlockLen[k] = numBlocks;
    blockCount += numBlocks;
}

// Compute per-cluster bounding boxes (only real vectors, not padding)
var bboxMin = new short[K * Dims];
var bboxMax = new short[K * Dims];
Array.Fill(bboxMin, short.MaxValue);
Array.Fill(bboxMax, short.MinValue);
for (int k = 0; k < K; k++)
{
    var members = clusterMembers[k];
    if (members.Count == 0) { Array.Fill(bboxMin, (short)0, k * Dims, Dims); Array.Fill(bboxMax, (short)0, k * Dims, Dims); continue; }
    for (int d = 0; d < Dims; d++)
    {
        short mn = short.MaxValue, mx = short.MinValue;
        foreach (int idx in members) { short v = allVecs[idx * 16 + d]; if (v < mn) mn = v; if (v > mx) mx = v; }
        bboxMin[k * Dims + d] = mn;
        bboxMax[k * Dims + d] = mx;
    }
}

using var bw = new BinaryWriter(File.Create(output));

// Header
bw.Write(Magic);
bw.Write(blockCount);
bw.Write(total);
bw.Write(K);

// Centroids (K * 16 floats)
for (int i = 0; i < K * 16; i++)
    bw.Write(centroids[i]);

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
    {
        WriteBlock(bw, allVecs, members, bi * BlockSize, Math.Min(BlockSize, members.Count - bi * BlockSize));
    }
}

// Labels (ordered by cluster, including padding as 0)
for (int k = 0; k < K; k++)
{
    var members = clusterMembers[k];
    int numBlocks = clusterBlockLen[k];
    for (int bi = 0; bi < numBlocks; bi++)
    {
        for (int pos = 0; pos < BlockSize; pos++)
        {
            int memberPos = bi * BlockSize + pos;
            bw.Write(memberPos < members.Count ? allLabels[members[memberPos]] : (byte)0);
        }
    }
}

Console.WriteLine($"Done. total={total}, K={K}, blockCount={blockCount}");

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
    // First centroid: random sample
    int first = sample[rng.Next(sample.Length)] * 16;
    for (int d = 0; d < Dims; d++) centroids[d] = vecs[first + d];

    var minDist = new float[sample.Length];
    minDist.AsSpan().Fill(float.MaxValue);

    for (int ci = 1; ci < k; ci++)
    {
        // Update min distances — each si writes only minDist[si], safe to parallelize
        int prevCBase = (ci - 1) * 16;
        Parallel.For(0, sample.Length, si =>
        {
            float d = CentroidDist(vecs, sample[si] * 16, centroids, prevCBase);
            if (d < minDist[si]) minDist[si] = d;
        });
        // Pick next centroid with probability proportional to minDist^2
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

// Search only centroids [start..start+count) — returns index relative to start
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
        // Parallel assignment
        Parallel.For(0, sampleIdx.Length, si =>
            tempAssign[si] = NearestCentroidInRange(vecs, sampleIdx[si] * 16, centroids, 0, k));

        // Parallel accumulation with thread-local buffers merged at end
        Array.Clear(newCentroids);
        Array.Clear(counts);
        Parallel.For(0, sampleIdx.Length,
            () => (Acc: new float[k * 16], Cnt: new int[k]),
            (si, _, local) =>
            {
                int ck = tempAssign[si];
                int vb = sampleIdx[si] * 16;
                for (int d = 0; d < Dims; d++)
                    local.Acc[ck * 16 + d] += vecs[vb + d];
                local.Cnt[ck]++;
                return local;
            },
            local =>
            {
                lock (newCentroids)
                {
                    for (int i = 0; i < k * 16; i++) newCentroids[i] += local.Acc[i];
                    for (int i = 0; i < k; i++) counts[i] += local.Cnt[i];
                }
            });

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

static unsafe void WriteBlock(BinaryWriter bw, short[] vecs, List<int> members, int start, int realCount)
{
    Block b = default;
    short* ptr = (short*)&b;
    for (int pos = 0; pos < BlockSize; pos++)
    {
        int memberPos = start + pos;
        int vb = memberPos < members.Count ? members[memberPos] * 16 : -1;
        for (int d = 0; d < Dims; d++)
            ptr[d * BlockSize + pos] = vb >= 0 ? vecs[vb + d] : PaddingSentinel;
    }
    bw.Write(new ReadOnlySpan<byte>(ptr, sizeof(Block)));
}
