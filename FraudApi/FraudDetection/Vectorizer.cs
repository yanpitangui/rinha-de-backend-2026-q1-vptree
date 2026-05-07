namespace FraudApi.FraudDetection;

public static class Vectorizer
{
    private const float Scale = 8192f;

    public static void Vectorize(Span<float> src, Span<short> dst)
    {
        // unrolled = faster (no bounds checks, no loop)
        dst[0]  = (short)(src[0]  * Scale);
        dst[1]  = (short)(src[1]  * Scale);
        dst[2]  = (short)(src[2]  * Scale);
        dst[3]  = (short)(src[3]  * Scale);
        dst[4]  = (short)(src[4]  * Scale);
        dst[5]  = (short)(src[5]  * Scale);
        dst[6]  = (short)(src[6]  * Scale);
        dst[7]  = (short)(src[7]  * Scale);
        dst[8]  = (short)(src[8]  * Scale);
        dst[9]  = (short)(src[9]  * Scale);
        dst[10] = (short)(src[10] * Scale);
        dst[11] = (short)(src[11] * Scale);
        dst[12] = (short)(src[12] * Scale);
        dst[13] = (short)(src[13] * Scale);

        // padding for SIMD (important)
        dst[14] = 0;
        dst[15] = 0;
    }
}