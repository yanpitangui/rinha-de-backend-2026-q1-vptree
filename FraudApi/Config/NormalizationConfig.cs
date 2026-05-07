namespace FraudApi.Config;

using System.Text.Json.Serialization;

public sealed class NormalizationConfig
{
    [JsonPropertyName("max_amount")]
    public double MaxAmount { get; set; }

    [JsonPropertyName("max_installments")]
    public double MaxInstallments { get; set; }

    [JsonPropertyName("amount_vs_avg_ratio")]
    public double AmountVsAvgRatio { get; set; }

    [JsonPropertyName("max_minutes")]
    public double MaxMinutes { get; set; }

    [JsonPropertyName("max_km")]
    public double MaxKm { get; set; }

    [JsonPropertyName("max_tx_count_24h")]
    public double MaxTxCount24h { get; set; }

    [JsonPropertyName("max_merchant_avg_amount")]
    public double MaxMerchantAvgAmount { get; set; }
}
