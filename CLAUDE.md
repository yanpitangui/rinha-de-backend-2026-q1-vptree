# Rinha de Backend 2026 – Fraud Detection (C# submission)

## Goal

Win (or rank first among C# submissions) in Rinha de Backend 2026. Score = `score_p99 + score_det`, max 6000. Both latency and detection quality matter equally.

## Challenge summary

Build a fraud-detection API that, for every incoming card transaction:
1. Vectorizes the payload into a 14-dimensional float vector.
2. Finds the 5 nearest neighbors in a reference dataset of 3,000,000 labeled vectors.
3. Returns `fraud_score = fraud_count / 5` and `approved = fraud_score < 0.6`.

## API contract (port 9999)

```
GET  /ready        → 2xx when the service is ready
POST /fraud-score  → { "approved": bool, "fraud_score": float }
```

Request body shape (see `docs/en/API.md` in the rules repo for full field table):
```json
{
  "id": "tx-123",
  "transaction":      { "amount": 384.88, "installments": 3, "requested_at": "2026-03-11T20:23:35Z" },
  "customer":         { "avg_amount": 769.76, "tx_count_24h": 3, "known_merchants": ["MERC-001"] },
  "merchant":         { "id": "MERC-001", "mcc": "5912", "avg_amount": 298.95 },
  "terminal":         { "is_online": false, "card_present": true, "km_from_home": 13.7 },
  "last_transaction": { "timestamp": "2026-03-11T14:58:35Z", "km_from_current": 18.86 }
}
```
`last_transaction` may be `null`.

## Vectorization – 14 dimensions (exact, do not change)

| idx | dimension              | formula |
|-----|------------------------|---------|
| 0   | amount                 | `clamp(amount / 10000)` |
| 1   | installments           | `clamp(installments / 12)` |
| 2   | amount_vs_avg          | `clamp((amount / avg_amount) / 10)` |
| 3   | hour_of_day            | `hour_utc / 23` |
| 4   | day_of_week            | `day_of_week / 6` (mon=0, sun=6) |
| 5   | minutes_since_last_tx  | `clamp(minutes / 1440)` or **`-1`** if `last_transaction` is null |
| 6   | km_from_last_tx        | `clamp(km_from_current / 1000)` or **`-1`** if `last_transaction` is null |
| 7   | km_from_home           | `clamp(km_from_home / 1000)` |
| 8   | tx_count_24h           | `clamp(tx_count_24h / 20)` |
| 9   | is_online              | `1` if online, else `0` |
| 10  | card_present           | `1` if present, else `0` |
| 11  | unknown_merchant       | `1` if `merchant.id` NOT in `known_merchants`, else `0` |
| 12  | mcc_risk               | `mcc_risk.json[mcc]` (default `0.5`) |
| 13  | merchant_avg_amount    | `clamp(merchant.avg_amount / 10000)` |

`clamp(x) = max(0.0, min(1.0, x))`

The `-1` sentinel at indices 5 and 6 is intentional — do not replace or filter it.

## Reference dataset

`resources/references.json.gz` — 3M records `{ "vector": [14 floats], "label": "fraud"|"legit" }`.
`resources/mcc_risk.json` — MCC → risk float.
`resources/normalization.json` — the constants above.

These files **never change** during a test run. Pre-process everything at container build or startup.

## Scoring

```
score_p99  = 1000 * log10(1000 / max(p99_ms, 1))   [capped −3000..+3000; −3000 if p99 > 2000ms]
score_det  = 1000 * log10(1/ε) − 300 * log10(1+E)  [−3000 if failure_rate > 15%]

E          = 1·FP + 3·FN + 5·Err    (weighted errors)
ε          = E / N
failure_rate = (FP + FN + Err) / N

final_score = score_p99 + score_det
```

Key takeaways:
- HTTP 500 costs 5× more than a false positive. Never crash — return a fallback `{approved:true, fraud_score:0.0}` in the worst case.
- Each 10× latency improvement = +1000 points. Sub-1ms p99 saturates at +3000.
- Stay under 15% failure rate at all costs; crossing it locks `score_det` at −3000.

## Infrastructure constraints (non-negotiable)

- At least **1 load balancer + 2 API instances** in round-robin.
- Load balancer must NOT inspect payloads or apply business logic.
- `docker-compose.yml` on `submission` branch; all images public, linux-amd64.
- Total resource limits across all services: **≤ 1 CPU, ≤ 350 MB RAM**.
- Port **9999** exposed by the load balancer.
- Network mode: `bridge` only. No `host`, no `privileged`.

## Current implementation (WIP)

- **Stack**: .NET 11 preview, AOT-compiled (`PublishAot=true`), alpine linux-musl-x64.
- **PreProcessor** (`FraudApi.PreProcessor/`): streams `references.json.gz`, quantizes each float to `int16` with scale 8192, writes a column-oriented binary `dataset.bin`. Block size = 64 vectors. Layout: `[blockCount int32][total int32][Block[blockCount]][labels byte[total]]`.
- **Block** (`FraudApi.Shared/Block.cs`): struct with 14 fixed `short[64]` arrays (column-major for SIMD).
- **MmapData** (`FraudApi/Data/MmapData.cs`): loads `dataset.bin` via `MemoryMappedFile` → raw pointers.
- **SearchEngine** (`FraudApi/FraudDetection/SearchEngine.cs`): brute-force KNN k=5, AVX2 SIMD per-dimension squared-distance accumulation, block-level top-k maintenance.
- **FraudHandler** (`FraudApi/FraudDetection/FraudHandler.cs`): static entry point, pre-built response bytes for the 6 possible scores (0/5..5/5).
- **Vectorizer/Normalizer/FeatureExtractor** in `FraudApi/FraudDetection/`: converts request → `Span<short>` query.

## Build commands

```bash
# Run the preprocessor (once, generates resources/dataset.bin)
dotnet run --project FraudApi.PreProcessor/FraudApi.PreProcessor.csproj

# Run the API locally
dotnet run --project FraudApi/FraudApi.csproj

# Build the Docker image
docker build -t fraud-api .
```

## Performance notes

- The brute-force search is O(N×14) = O(42M) operations per request. With 3M vectors and AVX2 it is viable but may not reach sub-1ms p99 at scale.
- Consider ANN structures (HNSW, VP-Tree, IVF) if brute-force latency is the bottleneck.
- The two API instances share no state — the reference dataset is read-only. Pre-load and pin it into memory.
- AOT + `WebApplication.CreateSlimBuilder` already eliminates most startup overhead.
- The 6-response pre-allocation (`BuildResponses()`) avoids serialization at request time — keep this pattern.
- Do NOT use the test payloads as reference data; the final test uses different payloads.
