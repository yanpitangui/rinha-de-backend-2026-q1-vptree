using System.Runtime.CompilerServices;

namespace FraudApi.FraudDetection;

public sealed class ProfileFastPath
{
    // 23-bit key (sum=23 → 8M entries × 2B = 16 MiB): highest-variance dims get most bits.
    // Dims 6 (km_from_last_tx) and 5 (minutes_since_last_tx) included — strongest fraud signal.
    // MUST stay in sync with FraudApi.PreProcessor/Program.cs BuildFastPath().
    private static readonly int[] FeatureIndex = [6,  2,  5, 0, 12, 7, 9, 10, 11];
    private static readonly int[] Bits         = [6,  4,  3, 3,  2, 2, 1,  1,  1]; // sum=23 → 8M entries × 2B = 16 MiB

    private static readonly int[] Shifts;

    static ProfileFastPath()
    {
        Shifts = new int[FeatureIndex.Length];
        for (int f = 1; f < FeatureIndex.Length; f++)
            Shifts[f] = Shifts[f - 1] + Bits[f - 1];
    }

    private readonly short[][] _edges;
    // entry = (legit_count << 8) | fraud_count  (each field capped at 255)
    private readonly ushort[] _table;

    // Runtime-configurable thresholds (env vars, tunable without rebuild).
    private readonly int _pureLegitMin; // pure-legit  : fraud==0 AND total >= this
    private readonly int _pureFraudMin; // pure-fraud  : legit==0 AND total >= this
    private readonly int _domLegitMin;  // dominant legit: fraud<=1 AND total >= this
    private readonly int _domFraudMin;  // dominant fraud: legit<=1 AND total >= this

    private ProfileFastPath(short[][] edges, ushort[] table)
    {
        _edges = edges;
        _table = table;
        _pureLegitMin = Env("FP_PURE_LEGIT_MIN", 5);
        _pureFraudMin = Env("FP_PURE_FRAUD_MIN", 10);
        _domLegitMin  = Env("FP_DOM_LEGIT_MIN",  50);
        _domFraudMin  = Env("FP_DOM_FRAUD_MIN",  50);
    }

    private static int Env(string name, int def) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var v) ? v : def;

    public static ProfileFastPath Load(string path)
    {
        using var br = new BinaryReader(File.OpenRead(path));
        int magic = br.ReadInt32();
        if (magic != unchecked((int)0x46415333))
            throw new InvalidDataException($"fastpath.bin: expected magic FAS3, got 0x{magic:X8}");

        int nf = FeatureIndex.Length;
        var edges = new short[nf][];
        for (int f = 0; f < nf; f++)
        {
            int count = br.ReadInt32();
            edges[f] = new short[count];
            for (int i = 0; i < count; i++)
                edges[f][i] = br.ReadInt16();
        }

        int tableSize = br.ReadInt32();
        var table = new ushort[tableSize];
        for (int i = 0; i < tableSize; i++)
            table[i] = br.ReadUInt16();
        return new ProfileFastPath(edges, table);
    }

    // Returns: 0=miss (do full search), 1=fc0 (approved), 6=fc5 (denied).
    // Caller: if result != 0, return Responses[result - 1].
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte TryLookup(Span<short> query)
    {
        uint key = 0;
        for (int f = 0; f < FeatureIndex.Length; f++)
            key |= (uint)FindBin(_edges[f], query[FeatureIndex[f]]) << Shifts[f];

        ushort entry = _table[key];
        if (entry == 0) return 0;

        int fraud = entry & 0xFF;
        int legit = entry >> 8;
        int total = legit + fraud;

        if (fraud == 0)
        {
            if (total >= _pureLegitMin)  return 1; // fc=0, approved
        }
        else if (legit == 0)
        {
            if (total >= _pureFraudMin)  return 6; // fc=5, denied
        }
        else if (fraud == 1 && total >= _domLegitMin) return 1;
        else if (legit == 1 && total >= _domFraudMin) return 6;

        return 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindBin(short[] edges, short v)
    {
        int lo = 0, hi = edges.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (v < edges[mid]) hi = mid; else lo = mid + 1;
        }
        return lo;
    }
}
