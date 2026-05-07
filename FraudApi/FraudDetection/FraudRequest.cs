namespace FraudApi.FraudDetection;

using System.Text.Json.Serialization;

public sealed class FraudRequest
{
    [JsonPropertyName("transaction")]
    public Transaction Transaction { get; set; } = default!;

    [JsonPropertyName("customer")]
    public Customer Customer { get; set; } = default!;

    [JsonPropertyName("merchant")]
    public Merchant Merchant { get; set; } = default!;

    [JsonPropertyName("terminal")]
    public Terminal Terminal { get; set; } = default!;

    [JsonPropertyName("last_transaction")]
    public LastTransaction? LastTransaction { get; set; }
}

public sealed class Transaction
{
    [JsonPropertyName("amount")]
    public double Amount { get; set; }

    [JsonPropertyName("installments")]
    public int Installments { get; set; }

    [JsonPropertyName("requested_at")]
    public string RequestedAt { get; set; } = default!;
}

public sealed class Customer
{
    [JsonPropertyName("avg_amount")]
    public double AvgAmount { get; set; }

    [JsonPropertyName("tx_count_24h")]
    public int TxCount24h { get; set; }

    [JsonPropertyName("known_merchants")]
    public string[] KnownMerchants { get; set; } = default!;
}

public sealed class Merchant
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = default!;

    [JsonPropertyName("mcc")]
    public string Mcc { get; set; } = default!;

    [JsonPropertyName("avg_amount")]
    public double AvgAmount { get; set; }
}

public sealed class Terminal
{
    [JsonPropertyName("is_online")]
    public bool IsOnline { get; set; }

    [JsonPropertyName("card_present")]
    public bool CardPresent { get; set; }

    [JsonPropertyName("km_from_home")]
    public double KmFromHome { get; set; }
}

public sealed class LastTransaction
{
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = default!;

    [JsonPropertyName("km_from_current")]
    public double KmFromCurrent { get; set; }
}