namespace FraudApi.Config;

using System.Text.Json.Serialization;

public sealed class NormalizationConfig
{
    [JsonPropertyName("max_amount")]
    public float MaxAmount { get; set; }

    [JsonPropertyName("max_installments")]
    public float MaxInstallments { get; set; }

    [JsonPropertyName("amount_vs_avg_ratio")]
    public float AmountVsAvgRatio { get; set; }

    [JsonPropertyName("max_minutes")]
    public float MaxMinutes { get; set; }

    [JsonPropertyName("max_km")]
    public float MaxKm { get; set; }

    [JsonPropertyName("max_tx_count_24h")]
    public float MaxTxCount24h { get; set; }

    [JsonPropertyName("max_merchant_avg_amount")]
    public float MaxMerchantAvgAmount { get; set; }
}