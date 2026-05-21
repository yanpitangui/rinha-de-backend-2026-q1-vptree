using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text.Json;
using FraudApi.Config;

namespace FraudApi.FraudDetection;

public static class DirectHandler
{
    private static readonly int[] s_dowTab = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    private static readonly int[] s_doy    = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    // Precomputed inverse normalization constants for SIMD batch:
    // [1/MaxAmount, 1/MaxInstallments, 1/AmountVsAvgRatio, 1/MaxMinutes,
    //  1/MaxKm, 1/MaxKm, 1/MaxTxCount24h, 1/MaxMerchantAvgAmount]
    private static Vector256<float> s_invMul;

    public static void Init(NormalizationConfig n)
    {
        s_invMul = Vector256.Create(
            1f / (float)n.MaxAmount,
            1f / (float)n.MaxInstallments,
            1f / (float)n.AmountVsAvgRatio,
            1f / (float)n.MaxMinutes,
            1f / (float)n.MaxKm,
            1f / (float)n.MaxKm,
            1f / (float)n.MaxTxCount24h,
            1f / (float)n.MaxMerchantAvgAmount);
    }

    internal static int ComputeIndex(ReadOnlySpan<byte> body)
    {
        Span<short> query = stackalloc short[16];
        Span<float> qf    = stackalloc float[16];
        if (!TryVectorize(body, query, qf, FraudHandler.MccRisk, FraudHandler.Norm))
            return 0;

        if (FraudHandler.FastPath is { } fp)
        {
            byte fpr = fp.TryLookup(query);
            if (fpr != 0) return fpr - 1;
        }

        return FraudHandler.Engine.Search(query, qf);
    }

    public static Task Handle(HttpContext ctx)
    {
        if (ctx.Request.BodyReader.TryRead(out var readResult))
        {
            var buffer = readResult.Buffer;
            byte[] resp = ComputeResponse(buffer);
            ctx.Request.BodyReader.AdvanceTo(buffer.End);
            ctx.Response.ContentType = "application/json";
            ctx.Response.ContentLength = resp.Length;
            ctx.Response.BodyWriter.Write(resp);
            return Task.CompletedTask;
        }
        return HandleAsync(ctx);
    }

    private static async Task HandleAsync(HttpContext ctx)
    {
        var readResult = await ctx.Request.BodyReader.ReadAsync();
        var buffer = readResult.Buffer;
        byte[] resp = ComputeResponse(buffer);
        ctx.Request.BodyReader.AdvanceTo(buffer.End);
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength = resp.Length;
        await ctx.Response.BodyWriter.WriteAsync(resp);
    }

    private static byte[] ComputeResponse(ReadOnlySequence<byte> buffer)
    {
        Span<short> query = stackalloc short[16];
        Span<float> qf    = stackalloc float[16];
        bool ok = buffer.IsSingleSegment
            ? TryVectorize(buffer.FirstSpan, query, qf, FraudHandler.MccRisk, FraudHandler.Norm)
            : TryVectorizeMultiSeg(buffer, query, qf, FraudHandler.MccRisk, FraudHandler.Norm);

        if (!ok) return FraudHandler.Responses[0];

        if (FraudHandler.FastPath is { } fp)
        {
            byte fpr = fp.TryLookup(query);
            if (fpr != 0) return FraudHandler.Responses[fpr - 1];
        }

        return FraudHandler.Responses[FraudHandler.Engine.Search(query, qf)];
    }

    private static bool TryVectorizeMultiSeg(ReadOnlySequence<byte> buffer, Span<short> dst, Span<float> fDst,
        Dictionary<int, double> mccRisk, NormalizationConfig n)
    {
        int len = (int)buffer.Length;
        var arr = ArrayPool<byte>.Shared.Rent(len);
        buffer.CopyTo(arr);
        bool ok = TryVectorize(new ReadOnlySpan<byte>(arr, 0, len), dst, fDst, mccRisk, n);
        ArrayPool<byte>.Shared.Return(arr);
        return ok;
    }

    private static bool TryVectorize(ReadOnlySpan<byte> body, Span<short> dst, Span<float> fDst,
        Dictionary<int, double> mccRisk, NormalizationConfig n)
    {
        var reader = new Utf8JsonReader(body);

        float amount = 0, avgAmount = 1, merchantAvgAmount = 0, kmFromHome = 0, kmFromCurrent = 0;
        int installments = 0, txCount24h = 0, mcc = 0;
        bool isOnline = false, cardPresent = false, hasLastTx = false;

        Span<byte> reqAt = stackalloc byte[20];
        Span<byte> lastAt = stackalloc byte[20];

        // up to 8 known merchants, 32 bytes each
        Span<byte> knownBuf = stackalloc byte[8 * 32];
        Span<int> knownLens = stackalloc int[8];
        int knownCount = 0;

        Span<byte> merchantIdBuf = stackalloc byte[32];
        int merchantIdLen = 0;

        byte section = 0; // 0=root 1=transaction 2=customer 3=known_merchants[] 4=merchant 5=terminal 6=lastTx
        byte field = 0;
        bool pendingLastTx = false;

        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        if (pendingLastTx) { section = 6; pendingLastTx = false; hasLastTx = true; }
                        break;

                    case JsonTokenType.EndObject:
                        if (section != 0) { section = 0; field = 0; }
                        break;

                    case JsonTokenType.StartArray:
                        if (section == 2 && field == 3) section = 3;
                        break;

                    case JsonTokenType.EndArray:
                        if (section == 3) { section = 2; field = 0; }
                        break;

                    case JsonTokenType.Null:
                        if (pendingLastTx) pendingLastTx = false;
                        break;

                    case JsonTokenType.PropertyName:
                        var prop = reader.ValueSpan;
                        switch (section)
                        {
                            case 0:
                                // unique by first byte; 't' needs length to distinguish transaction(11) vs terminal(8)
                                switch (prop[0])
                                {
                                    case (byte)'t':
                                        if (prop.Length == 11) { section = 1; field = 0; }      // transaction
                                        else if (prop.Length == 8) { section = 5; field = 0; }  // terminal
                                        break;
                                    case (byte)'c': section = 2; field = 0; break; // customer
                                    case (byte)'m': section = 4; field = 0; break; // merchant
                                    case (byte)'l': pendingLastTx = true; break;   // last_transaction
                                }
                                break;
                            case 1: // a=amount i=installments r=requested_at
                                field = prop[0] == (byte)'a' ? (byte)1
                                    : prop[0] == (byte)'i' ? (byte)2
                                    : prop[0] == (byte)'r' ? (byte)3
                                    : (byte)0;
                                break;
                            case 2: // a=avg_amount t=tx_count_24h k=known_merchants
                                field = prop[0] == (byte)'a' ? (byte)1
                                    : prop[0] == (byte)'t' ? (byte)2
                                    : prop[0] == (byte)'k' ? (byte)3
                                    : (byte)0;
                                break;
                            case 4: // i=id m=mcc a=avg_amount
                                field = prop[0] == (byte)'i' ? (byte)1
                                    : prop[0] == (byte)'m' ? (byte)2
                                    : prop[0] == (byte)'a' ? (byte)3
                                    : (byte)0;
                                break;
                            case 5: // i=is_online c=card_present k=km_from_home
                                field = prop[0] == (byte)'i' ? (byte)1
                                    : prop[0] == (byte)'c' ? (byte)2
                                    : prop[0] == (byte)'k' ? (byte)3
                                    : (byte)0;
                                break;
                            case 6: // t=timestamp k=km_from_current
                                field = prop[0] == (byte)'t' ? (byte)1
                                    : prop[0] == (byte)'k' ? (byte)2
                                    : (byte)0;
                                break;
                        }
                        break;

                    case JsonTokenType.Number:
                        switch (section)
                        {
                            case 1:
                                if (field == 1) amount = reader.GetSingle();
                                else if (field == 2) installments = reader.GetInt32();
                                break;
                            case 2:
                                if (field == 1) avgAmount = reader.GetSingle();
                                else if (field == 2) txCount24h = reader.GetInt32();
                                break;
                            case 4:
                                if (field == 3) merchantAvgAmount = reader.GetSingle();
                                break;
                            case 5:
                                if (field == 3) kmFromHome = reader.GetSingle();
                                break;
                            case 6:
                                if (field == 2) kmFromCurrent = reader.GetSingle();
                                break;
                        }
                        break;

                    case JsonTokenType.String:
                        switch (section)
                        {
                            case 1:
                                if (field == 3)
                                {
                                    var vs = reader.ValueSpan;
                                    if (vs.Length >= 20) vs[..20].CopyTo(reqAt);
                                }
                                break;
                            case 3:
                                if (knownCount < 8)
                                {
                                    var vs = reader.ValueSpan;
                                    int vlen = Math.Min(vs.Length, 32);
                                    vs[..vlen].CopyTo(knownBuf.Slice(knownCount * 32));
                                    knownLens[knownCount++] = vlen;
                                }
                                break;
                            case 4:
                                if (field == 1)
                                {
                                    var vs = reader.ValueSpan;
                                    merchantIdLen = Math.Min(vs.Length, 32);
                                    vs[..merchantIdLen].CopyTo(merchantIdBuf);
                                }
                                else if (field == 2)
                                {
                                    mcc = ParseMcc(reader.ValueSpan);
                                }
                                break;
                            case 6:
                                if (field == 1)
                                {
                                    var vs = reader.ValueSpan;
                                    if (vs.Length >= 20) vs[..20].CopyTo(lastAt);
                                }
                                break;
                        }
                        break;

                    case JsonTokenType.True:
                        if (section == 5)
                        {
                            if (field == 1) isOnline = true;
                            else if (field == 2) cardPresent = true;
                        }
                        break;
                    // False: booleans default to false
                }
            }
        }
        catch { return false; }

        const int Scale = Vectorizer.Scale;

        var (hour, dow) = ParseUtcHourDow(reqAt);
        dst[3] = Vectorizer.HourLut[hour];
        dst[4] = Vectorizer.DowLut[dow];
        dst[9]  = isOnline ? (short)Scale : (short)0;
        dst[10] = cardPresent ? (short)Scale : (short)0;

        bool knownMerchant = false;
        var mid = merchantIdBuf[..merchantIdLen];
        for (int i = 0; i < knownCount; i++)
        {
            if (knownLens[i] == merchantIdLen && knownBuf.Slice(i * 32, knownLens[i]).SequenceEqual(mid))
            {
                knownMerchant = true;
                break;
            }
        }
        dst[11] = knownMerchant ? (short)0 : (short)Scale;
        dst[12] = FraudHandler.MccLut[mcc];
        dst[14] = 0;
        dst[15] = 0;

        if (Avx2.IsSupported)
        {
            float minutesDiff = hasLastTx ? MinutesDiff(lastAt, reqAt) : 0f;
            float kmCurrent   = hasLastTx ? kmFromCurrent : 0f;

            // 8 dims in one AVX2 pass: [amount, installments, ratio, minutes, kmCurrent, kmHome, txCount, merchantAvg]
            var vals      = Vector256.Create(amount, (float)installments, amount / avgAmount,
                                             minutesDiff, kmCurrent, kmFromHome,
                                             (float)txCount24h, merchantAvgAmount);
            var clamped   = Avx.Max(Vector256<float>.Zero, Avx.Min(Avx.Multiply(vals, s_invMul), Vector256.Create(1f)));
            // VCVTPS2DQ rounds to nearest-even, matching MathF.Round behavior
            var quantized = Avx.ConvertToVector256Int32(Avx.Multiply(clamped, Vector256.Create((float)Scale)));
            var packed    = Sse2.PackSignedSaturate(quantized.GetLower(), quantized.GetUpper());

            dst[0]  = (short)packed.GetElement(0);
            dst[1]  = (short)packed.GetElement(1);
            dst[2]  = (short)packed.GetElement(2);
            dst[7]  = (short)packed.GetElement(5);
            dst[8]  = (short)packed.GetElement(6);
            dst[13] = (short)packed.GetElement(7);

            if (!hasLastTx) { dst[5] = (short)(-Scale); dst[6] = (short)(-Scale); }
            else            { dst[5] = (short)packed.GetElement(3); dst[6] = (short)packed.GetElement(4); }

            fDst[0]  = clamped.GetElement(0);
            fDst[1]  = clamped.GetElement(1);
            fDst[2]  = clamped.GetElement(2);
            fDst[3]  = hour / 23f;
            fDst[4]  = dow / 6f;
            fDst[5]  = hasLastTx ? clamped.GetElement(3) : -1f;
            fDst[6]  = hasLastTx ? clamped.GetElement(4) : -1f;
            fDst[7]  = clamped.GetElement(5);
            fDst[8]  = clamped.GetElement(6);
            fDst[9]  = isOnline    ? 1f : 0f;
            fDst[10] = cardPresent ? 1f : 0f;
            fDst[11] = knownMerchant ? 0f : 1f;
            fDst[12] = FraudHandler.MccLut[mcc] * (1f / Scale);
            fDst[13] = clamped.GetElement(7);
        }
        else
        {
            dst[0] = Q(Clamp(amount / (float)n.MaxAmount));
            dst[1] = Q(Clamp(installments / (float)n.MaxInstallments));
            dst[2] = Q(Clamp(amount / avgAmount / (float)n.AmountVsAvgRatio));
            if (!hasLastTx)
            {
                dst[5] = (short)(-Scale);
                dst[6] = (short)(-Scale);
            }
            else
            {
                dst[5] = Q(Clamp(MinutesDiff(lastAt, reqAt) / (float)n.MaxMinutes));
                dst[6] = Q(Clamp(kmFromCurrent / (float)n.MaxKm));
            }
            dst[7]  = Q(Clamp(kmFromHome / (float)n.MaxKm));
            dst[8]  = Q(Clamp(txCount24h / (float)n.MaxTxCount24h));
            dst[13] = Q(Clamp(merchantAvgAmount / (float)n.MaxMerchantAvgAmount));

            fDst[0]  = Clamp(amount / (float)n.MaxAmount);
            fDst[1]  = Clamp(installments / (float)n.MaxInstallments);
            fDst[2]  = Clamp(amount / avgAmount / (float)n.AmountVsAvgRatio);
            fDst[3]  = hour / 23f;
            fDst[4]  = dow / 6f;
            fDst[5]  = hasLastTx ? Clamp(MinutesDiff(lastAt, reqAt) / (float)n.MaxMinutes) : -1f;
            fDst[6]  = hasLastTx ? Clamp(kmFromCurrent / (float)n.MaxKm) : -1f;
            fDst[7]  = Clamp(kmFromHome / (float)n.MaxKm);
            fDst[8]  = Clamp(txCount24h / (float)n.MaxTxCount24h);
            fDst[9]  = isOnline    ? 1f : 0f;
            fDst[10] = cardPresent ? 1f : 0f;
            fDst[11] = knownMerchant ? 0f : 1f;
            fDst[12] = FraudHandler.MccLut[mcc] * (1f / Scale);
            fDst[13] = Clamp(merchantAvgAmount / (float)n.MaxMerchantAvgAmount);
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ParseMcc(ReadOnlySpan<byte> s) =>
        s.Length < 4 ? 0
        : (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static (byte hour, byte dow) ParseUtcHourDow(ReadOnlySpan<byte> s)
    {
        int y  = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
        int mo = (s[5] - '0') * 10 + (s[6] - '0');
        int d  = (s[8] - '0') * 10 + (s[9] - '0');
        int h  = (s[11] - '0') * 10 + (s[12] - '0');
        int dw = (DayOfWeekFast(y, mo, d) + 6) % 7;
        return ((byte)h, (byte)dw);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DayOfWeekFast(int y, int m, int d)
    {
        if (m < 3) y--;
        return (y + y / 4 - y / 100 + y / 400 + s_dowTab[m - 1] + d) % 7;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long DaysFromEpoch(int y, int m, int d)
    {
        int y1 = y - 1;
        bool leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        return 365L * y1 + y1 / 4 - y1 / 100 + y1 / 400
             + s_doy[m - 1] + (leap && m > 2 ? 1 : 0) + d - 1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float MinutesDiff(ReadOnlySpan<byte> from, ReadOnlySpan<byte> to)
    {
        var dtFrom = ParseUtcTicks(from);
        var dtTo   = ParseUtcTicks(to);
        return (float)((dtTo - dtFrom) / (double)TimeSpan.TicksPerMinute);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long ParseUtcTicks(ReadOnlySpan<byte> s)
    {
        int y   = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
        int mo  = (s[5] - '0') * 10 + (s[6] - '0');
        int d   = (s[8] - '0') * 10 + (s[9] - '0');
        int h   = (s[11] - '0') * 10 + (s[12] - '0');
        int mi  = (s[14] - '0') * 10 + (s[15] - '0');
        int sec = (s[17] - '0') * 10 + (s[18] - '0');
        return DaysFromEpoch(y, mo, d) * 864_000_000_000L
             + h * 36_000_000_000L + mi * 600_000_000L + sec * 10_000_000L;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static short Q(float v)
    {
        var q = (int)MathF.Round(v * Vectorizer.Scale);
        return q > short.MaxValue ? short.MaxValue : q < short.MinValue ? short.MinValue : (short)q;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float Clamp(float x) => x < 0f ? 0f : x > 1f ? 1f : x;
}
