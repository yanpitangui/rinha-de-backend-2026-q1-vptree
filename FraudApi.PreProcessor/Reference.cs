namespace FraudApi.PreProcessor;

using System.Text.Json.Serialization;

public sealed class Reference
{
    [JsonPropertyName("vector")]
    public double[] Vector { get; set; } = default!;

    [JsonPropertyName("label")]
    public string Label { get; set; } = default!;
}