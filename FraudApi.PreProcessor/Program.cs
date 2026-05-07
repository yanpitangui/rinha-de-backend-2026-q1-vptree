using System.IO.Compression;
using System.Text.Json;
using FraudApi.Shared;

const int Scale = 8192;
const int BlockSize = 64;

short Quantize(double v)
{
    var q = (int)Math.Round(v * Scale);
    if (q > short.MaxValue) q = short.MaxValue;
    if (q < short.MinValue) q = short.MinValue;
    return (short)q;
}

var resourcesPath =
    args.Length > 0
        ? args[0]
        : Environment.GetEnvironmentVariable("RESOURCES_PATH")
        ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../resources"));

var input = Path.Combine(resourcesPath, "references.json.gz");
var output = Path.Combine(resourcesPath, "dataset.bin");

Console.WriteLine($"Streaming dataset from: {input}");

using var fs = File.OpenRead(input);
using var gz = new GZipStream(fs, CompressionMode.Decompress);
using var bw = new BinaryWriter(File.Create(output));

// reserve header
bw.Write(0);
bw.Write(0);

int total = 0;
int blockCount = 0;

Block current = default;
int offset = 0;

var labels = new List<byte>(3_000_000);

// streaming buffer
byte[] buffer = new byte[64 * 1024];
int bytesInBuffer = 0;

var state = new JsonReaderState();

double[] vec = new double[14];
bool inVector = false;
int vi = 0;
bool isFraud = false;

void WriteBlock(BinaryWriter bw, ref Block blk)
{
    unsafe
    {
        fixed (short* d0 = blk.D0)
        fixed (short* d1 = blk.D1)
        fixed (short* d2 = blk.D2)
        fixed (short* d3 = blk.D3)
        fixed (short* d4 = blk.D4)
        fixed (short* d5 = blk.D5)
        fixed (short* d6 = blk.D6)
        fixed (short* d7 = blk.D7)
        fixed (short* d8 = blk.D8)
        fixed (short* d9 = blk.D9)
        fixed (short* d10 = blk.D10)
        fixed (short* d11 = blk.D11)
        fixed (short* d12 = blk.D12)
        fixed (short* d13 = blk.D13)
        {
            bw.Write(new ReadOnlySpan<byte>(d0, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d1, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d2, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d3, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d4, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d5, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d6, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d7, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d8, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d9, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d10, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d11, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d12, 64 * sizeof(short)));
            bw.Write(new ReadOnlySpan<byte>(d13, 64 * sizeof(short)));
        }
    }
}

void ProcessToken(ref Utf8JsonReader reader)
{
    if (reader.TokenType == JsonTokenType.PropertyName)
    {
        var name = reader.GetString();

        if (name == "vector")
        {
            reader.Read();
            inVector = true;
            vi = 0;
        }
        else if (name == "label")
        {
            reader.Read();
            isFraud = reader.GetString() == "fraud";
        }
    }
    else if (inVector && reader.TokenType == JsonTokenType.Number)
    {
        vec[vi++] = reader.GetDouble();
    }
    else if (reader.TokenType == JsonTokenType.EndArray && inVector)
    {
        inVector = false;
    }
    else if (reader.TokenType == JsonTokenType.EndObject)
    {
        unsafe
        {
            ref Block blk = ref current;

            blk.D0[offset] = Quantize(vec[0]);
            blk.D1[offset] = Quantize(vec[1]);
            blk.D2[offset] = Quantize(vec[2]);
            blk.D3[offset] = Quantize(vec[3]);
            blk.D4[offset] = Quantize(vec[4]);
            blk.D5[offset] = Quantize(vec[5]);
            blk.D6[offset] = Quantize(vec[6]);
            blk.D7[offset] = Quantize(vec[7]);
            blk.D8[offset] = Quantize(vec[8]);
            blk.D9[offset] = Quantize(vec[9]);
            blk.D10[offset] = Quantize(vec[10]);
            blk.D11[offset] = Quantize(vec[11]);
            blk.D12[offset] = Quantize(vec[12]);
            blk.D13[offset] = Quantize(vec[13]);

            labels.Add(isFraud ? (byte)1 : (byte)0);

            offset++;
            total++;

            if (offset == BlockSize)
            {
                WriteBlock(bw, ref current);
                current = default;
                offset = 0;
                blockCount++;
            }
        }
    }
}

while (true)
{
    if (bytesInBuffer == buffer.Length)
        throw new Exception("Buffer too small for JSON token");

    int bytesRead = gz.Read(buffer, bytesInBuffer, buffer.Length - bytesInBuffer);
    if (bytesRead == 0) break;

    bytesInBuffer += bytesRead;

    var reader = new Utf8JsonReader(
        new ReadOnlySpan<byte>(buffer, 0, bytesInBuffer),
        false,
        state);

    while (reader.Read())
    {
        ProcessToken(ref reader);
    }

    int consumed = (int)reader.BytesConsumed;

    Buffer.BlockCopy(buffer, consumed, buffer, 0, bytesInBuffer - consumed);
    bytesInBuffer -= consumed;

    state = reader.CurrentState;
}

// final pass
var finalReader = new Utf8JsonReader(
    new ReadOnlySpan<byte>(buffer, 0, bytesInBuffer),
    true,
    state);

while (finalReader.Read())
{
    ProcessToken(ref finalReader);
}

// flush last block
if (offset > 0)
{
    WriteBlock(bw, ref current);
    blockCount++;
}

// write labels
bw.Write(labels.ToArray());

// rewrite header
bw.Seek(0, SeekOrigin.Begin);
bw.Write(blockCount);
bw.Write(total);

Console.WriteLine($"Done. Total={total}, Blocks={blockCount}");