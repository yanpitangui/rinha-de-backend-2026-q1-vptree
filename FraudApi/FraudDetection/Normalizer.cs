using System.Runtime.CompilerServices;
using FraudApi.Config;

namespace FraudApi.FraudDetection;

public static class Normalizer
{
    public static void Normalize(Span<float> f, NormalizationConfig n)
    {
        f[0] = Clamp(f[0] / n.MaxAmount);

        f[1] = Clamp(f[1] / n.MaxInstallments);

        f[2] = Clamp(f[2] / n.AmountVsAvgRatio);

        f[3] = f[3] / 23f;

        f[4] = f[4] / 6f;

        if (f[5] != -1f)
            f[5] = Clamp(f[5] / n.MaxMinutes);

        if (f[6] != -1f)
            f[6] = Clamp(f[6] / n.MaxKm);

        f[7] = Clamp(f[7] / n.MaxKm);

        f[8] = Clamp(f[8] / n.MaxTxCount24h);

        // 9,10 already 0/1

        // 11 already 0/1

        // 12 already 0–1

        f[13] = Clamp(f[13] / n.MaxMerchantAvgAmount);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    static float Clamp(float x)
    {
        if (x < 0f) return 0f;
        if (x > 1f) return 1f;
        return x;
    }
}