using System.Runtime.CompilerServices;

namespace FraudApi.FraudDetection;

public sealed class ProfileFastPath
{
    // Feature dims to include in bucket key (tuned offline — same as rinha-backend-2026)
    private static readonly int[] FeatureIndex = [0, 7, 10, 1, 9, 11, 12, 3];
    // Bits per feature; sum must equal 24 (→ 16 MiB table)
    private static readonly int[] Bits = [4, 3, 6, 1, 3, 4, 1, 2];

    private static readonly int[] Shifts;

    static ProfileFastPath()
    {
        Shifts = new int[FeatureIndex.Length];
        Shifts[0] = 0;
        for (int f = 1; f < FeatureIndex.Length; f++)
            Shifts[f] = Shifts[f - 1] + Bits[f - 1];
    }

    private readonly short[][] _edges; // quantile thresholds per feature (int16 space)
    private readonly byte[] _table;   // 0=miss, 1=pure-legit, 2=pure-fraud

    private ProfileFastPath(short[][] edges, byte[] table)
    {
        _edges = edges;
        _table = table;
    }

    public static ProfileFastPath Load(string path)
    {
        using var br = new BinaryReader(File.OpenRead(path));
        int magic = br.ReadInt32();
        if (magic != unchecked((int)0x46415354))
            throw new InvalidDataException("fastpath.bin bad magic");

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
        var table = br.ReadBytes(tableSize);
        return new ProfileFastPath(edges, table);
    }

    // Returns 0=miss, 1=pure-legit, 2=pure-fraud.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte TryLookup(Span<short> query)
    {
        uint key = 0;
        for (int f = 0; f < FeatureIndex.Length; f++)
        {
            short v = query[FeatureIndex[f]];
            key |= (uint)FindBin(_edges[f], v) << Shifts[f];
        }
        return _table[key];
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
