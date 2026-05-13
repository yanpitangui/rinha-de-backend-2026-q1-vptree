namespace FraudApi.FraudDetection;

public static class Vectorizer
{
    public const int Scale = 10000;

    internal static readonly short[] HourLut = BuildLut(24, 23.0);
    internal static readonly short[] DowLut = BuildLut(7, 6.0);

    private static short[] BuildLut(int n, double divisor)
    {
        var arr = new short[n];
        for (int i = 0; i < n; i++)
            arr[i] = (short)Math.Round(i / divisor * Scale);
        return arr;
    }
}
