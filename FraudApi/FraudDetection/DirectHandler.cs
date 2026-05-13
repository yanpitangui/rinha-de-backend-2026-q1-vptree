using System.Buffers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using FraudApi.Config;

namespace FraudApi.FraudDetection;

public static class DirectHandler
{
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
        bool ok = buffer.IsSingleSegment
            ? TryVectorize(buffer.FirstSpan, query, FraudHandler.MccRisk, FraudHandler.Norm)
            : TryVectorizeMultiSeg(buffer, query, FraudHandler.MccRisk, FraudHandler.Norm);

        if (!ok) return FraudHandler.Responses[0];

        if (FraudHandler.FastPath is { } fp && fp.TryLookup(query) == 2)
            return FraudHandler.Responses[5];

        return FraudHandler.Responses[FraudHandler.Engine.Search(query)];
    }

    private static bool TryVectorizeMultiSeg(ReadOnlySequence<byte> buffer, Span<short> dst,
        Dictionary<int, double> mccRisk, NormalizationConfig n)
    {
        int len = (int)buffer.Length;
        var arr = ArrayPool<byte>.Shared.Rent(len);
        buffer.CopyTo(arr);
        bool ok = TryVectorize(new ReadOnlySpan<byte>(arr, 0, len), dst, mccRisk, n);
        ArrayPool<byte>.Shared.Return(arr);
        return ok;
    }

    private static bool TryVectorize(ReadOnlySpan<byte> body, Span<short> dst,
        Dictionary<int, double> mccRisk, NormalizationConfig n)
    {
        var reader = new Utf8JsonReader(body);

        double amount = 0, avgAmount = 1, merchantAvgAmount = 0, kmFromHome = 0, kmFromCurrent = 0;
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
                                if (field == 1) amount = reader.GetDouble();
                                else if (field == 2) installments = reader.GetInt32();
                                break;
                            case 2:
                                if (field == 1) avgAmount = reader.GetDouble();
                                else if (field == 2) txCount24h = reader.GetInt32();
                                break;
                            case 4:
                                if (field == 3) merchantAvgAmount = reader.GetDouble();
                                break;
                            case 5:
                                if (field == 3) kmFromHome = reader.GetDouble();
                                break;
                            case 6:
                                if (field == 2) kmFromCurrent = reader.GetDouble();
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

        dst[0] = Q(Clamp(amount / n.MaxAmount));
        dst[1] = Q(Clamp(installments / n.MaxInstallments));
        dst[2] = Q(Clamp(amount / avgAmount / n.AmountVsAvgRatio));

        var (hour, dow) = ParseUtcHourDow(reqAt);
        dst[3] = Vectorizer.HourLut[hour];
        dst[4] = Vectorizer.DowLut[dow];

        if (!hasLastTx)
        {
            dst[5] = (short)(-Scale);
            dst[6] = (short)(-Scale);
        }
        else
        {
            var dt = ParseUtcDateTime(reqAt);
            var prev = ParseUtcDateTime(lastAt);
            dst[5] = Q(Clamp((dt - prev).TotalMinutes / n.MaxMinutes));
            dst[6] = Q(Clamp(kmFromCurrent / n.MaxKm));
        }

        dst[7]  = Q(Clamp(kmFromHome / n.MaxKm));
        dst[8]  = Q(Clamp(txCount24h / n.MaxTxCount24h));
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
        dst[12] = Q(mccRisk.GetValueOrDefault(mcc, 0.5));
        dst[13] = Q(Clamp(merchantAvgAmount / n.MaxMerchantAvgAmount));
        dst[14] = 0;
        dst[15] = 0;

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
        int dw = ((int)new DateTime(y, mo, d).DayOfWeek + 6) % 7;
        return ((byte)h, (byte)dw);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static DateTime ParseUtcDateTime(ReadOnlySpan<byte> s)
    {
        int y   = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
        int mo  = (s[5] - '0') * 10 + (s[6] - '0');
        int d   = (s[8] - '0') * 10 + (s[9] - '0');
        int h   = (s[11] - '0') * 10 + (s[12] - '0');
        int mi  = (s[14] - '0') * 10 + (s[15] - '0');
        int sec = (s[17] - '0') * 10 + (s[18] - '0');
        return new DateTime(y, mo, d, h, mi, sec, DateTimeKind.Utc);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static short Q(double v)
    {
        var q = (int)Math.Round(v * Vectorizer.Scale);
        return q > short.MaxValue ? short.MaxValue : q < short.MinValue ? short.MinValue : (short)q;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double Clamp(double x) => x < 0.0 ? 0.0 : x > 1.0 ? 1.0 : x;
}
