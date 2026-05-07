namespace FraudApi.FraudDetection;

public static class FeatureExtractor
{
    public static void Extract(
        FraudRequest r,
        Span<float> f,
        Dictionary<int, float> mccRisk)
    {
        var t = r.Transaction;
        var c = r.Customer;
        var m = r.Merchant;
        var term = r.Terminal;

        // 0 amount (raw)
        f[0] = (float)t.Amount;

        // 1 installments
        f[1] = t.Installments;

        // 2 amount_vs_avg (raw ratio)
        f[2] = (float)(t.Amount / c.AvgAmount);

        // 3 hour_of_day (raw hour 0–23)
        var dt = DateTime.Parse(t.RequestedAt);
        f[3] = dt.Hour;

        // 4 day_of_week (0–6, monday=0)
        int dow = ((int)dt.DayOfWeek + 6) % 7;
        f[4] = dow;

        // 5 + 6 last transaction
        if (r.LastTransaction is null)
        {
            f[5] = -1f;
            f[6] = -1f;
        }
        else
        {
            var prev = DateTime.Parse(r.LastTransaction.Timestamp);

            f[5] = (float)(dt - prev).TotalMinutes;
            f[6] = (float)r.LastTransaction.KmFromCurrent;
        }

        // 7 km from home
        f[7] = (float)term.KmFromHome;

        // 8 tx_count_24h
        f[8] = c.TxCount24h;

        // 9 is_online
        f[9] = term.IsOnline ? 1f : 0f;

        // 10 card_present
        f[10] = term.CardPresent ? 1f : 0f;

        // 11 unknown_merchant (IMPORTANT: inverted)
        float unknown = 1f;
        var known = c.KnownMerchants;
        for (int i = 0; i < known.Length; i++)
        {
            if (known[i] == m.Id)
            {
                unknown = 0f;
                break;
            }
        }
        f[11] = unknown;

        // 12 mcc_risk
        int mcc = int.Parse(m.Mcc);
        f[12] = mccRisk.GetValueOrDefault(mcc, 0.5f);

        // 13 merchant_avg_amount
        f[13] = (float)m.AvgAmount;
    }
}