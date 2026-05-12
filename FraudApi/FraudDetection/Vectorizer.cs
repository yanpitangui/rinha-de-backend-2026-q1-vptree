using System.Runtime.CompilerServices;
using FraudApi.Config;

namespace FraudApi.FraudDetection;

public static class Vectorizer
{
    public const int Scale = 10000;

    // Precomputed LUTs for hour (0-23) and day-of-week (0-6, mon=0)
    private static readonly short[] HourLut = BuildLut(24, 23.0);
    private static readonly short[] DowLut = BuildLut(7, 6.0);

    private static short[] BuildLut(int n, double divisor)
    {
        var arr = new short[n];
        for (int i = 0; i < n; i++)
            arr[i] = (short)Math.Round(i / divisor * Scale);
        return arr;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Vectorize(FraudRequest r, Span<short> dst,
        Dictionary<int, double> mccRisk, NormalizationConfig n)
    {
        var t = r.Transaction;
        var c = r.Customer;
        var m = r.Merchant;
        var term = r.Terminal;

        var dt = ParseUtc(t.RequestedAt);
        int dow = ((int)dt.DayOfWeek + 6) % 7;

        dst[0]  = Q(Clamp(t.Amount / n.MaxAmount));
        dst[1]  = Q(Clamp(t.Installments / n.MaxInstallments));
        dst[2]  = Q(Clamp((t.Amount / c.AvgAmount) / n.AmountVsAvgRatio));
        dst[3]  = HourLut[dt.Hour];
        dst[4]  = DowLut[dow];

        if (r.LastTransaction is null)
        {
            dst[5] = -Scale;
            dst[6] = -Scale;
        }
        else
        {
            var prev = ParseUtc(r.LastTransaction.Timestamp);
            dst[5] = Q(Clamp((dt - prev).TotalMinutes / n.MaxMinutes));
            dst[6] = Q(Clamp(r.LastTransaction.KmFromCurrent / n.MaxKm));
        }

        dst[7]  = Q(Clamp(term.KmFromHome / n.MaxKm));
        dst[8]  = Q(Clamp(c.TxCount24h / n.MaxTxCount24h));
        dst[9]  = term.IsOnline ? (short)Scale : (short)0;
        dst[10] = term.CardPresent ? (short)Scale : (short)0;

        bool knownMerchant = false;
        var known = c.KnownMerchants;
        for (int i = 0; i < known.Length; i++)
        {
            if (known[i] == m.Id) { knownMerchant = true; break; }
        }
        dst[11] = knownMerchant ? (short)0 : (short)Scale;

        dst[12] = Q(mccRisk.GetValueOrDefault(int.Parse(m.Mcc), 0.5));
        dst[13] = Q(Clamp(m.AvgAmount / n.MaxMerchantAvgAmount));

        dst[14] = 0;
        dst[15] = 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static short Q(double v)
    {
        var q = (int)Math.Round(v * Scale);
        if (q > short.MaxValue) return short.MaxValue;
        if (q < short.MinValue) return short.MinValue;
        return (short)q;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double Clamp(double x) => x < 0.0 ? 0.0 : x > 1.0 ? 1.0 : x;

    // Fast fixed-format UTC parser: "YYYY-MM-DDTHH:MM:SSZ"
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static DateTime ParseUtc(string s)
    {
        int y   = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
        int mo  = (s[5] - '0') * 10 + (s[6] - '0');
        int d   = (s[8] - '0') * 10 + (s[9] - '0');
        int h   = (s[11] - '0') * 10 + (s[12] - '0');
        int mi  = (s[14] - '0') * 10 + (s[15] - '0');
        int sec = (s[17] - '0') * 10 + (s[18] - '0');
        return new DateTime(y, mo, d, h, mi, sec, DateTimeKind.Utc);
    }
}
