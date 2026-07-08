# AI Enrichment Adapter — Module 5.2

Implements the application's `AIPort` by calling a **configurable, provider-
agnostic** AI backend over HTTPS and mapping the reply onto a domain
`Recommendation`. Infrastructure layer; the domain imports no AI libraries and
the application never depends on an HTTP client — **httpx lives only here**.

## Architecture

```
StartAssessment (best-effort) ──▶ AIPort.recommend(finding)
                                         │
                          ┌──────────────┴───────────────┐
                          ▼                               ▼
                    PromptBuilder                   ProviderConfig  (openai/
                 (fixed system prompt,             openrouter/glm/anthropic/
                  sanitised finding data)          gemini — chosen by config)
                          │                               │
                          ▼                               ▼
                       AIClient (httpx) ──▶ provider.extract_text ──▶ ResponseParser
                     pooling · timeout · retry              (JSON → Enrichment)
                     · TLS verify · logging                        │
                          │  (any failure)                         ▼
                          ▼                              Recommendation
                    ErrorTranslator ──▶ AIError          (severity = finding's,
                 (no httpx escapes infra)                 never the model's)
```

## Request flow

1. `PromptBuilder` builds a **fixed** system prompt + a sanitised `<finding>` block.
2. The configured `ProviderConfig` builds the endpoint, headers, and payload.
3. `AIClient` POSTs it (pooled connection, timeout, retries, TLS verify).
4. `provider.extract_text` pulls the generated text; `ResponseParser` validates JSON.
5. The adapter maps the `Enrichment` to a `Recommendation`, keeping the finding's severity.

## Provider abstraction

No provider is hardcoded. `settings.ai.provider` selects a `ProviderConfig`
strategy: `openai` / `openrouter` / `glm` (OpenAI-compatible), `anthropic` /
`claude`, `gemini`. Adding a provider = one strategy + one registry entry.

## Security

- **Never logs** the API key (only in the auth header) or the prompt body.
- **`SecretStr`** for the key; `.get_secret_value()` is called once, only to build headers.
- **TLS verification on by default**; only an explicit `verify_ssl=false` disables it.
- **Outbound hygiene:** only title, severity label, description, and evidence are
  sent — never ids, config, paths, env vars, keys, or stack traces (redacted if present).
- **Severity is never taken from the model**; CVEs are not invented (instructed + not trusted).

## Prompt-injection protection

Scanner output is untrusted. The `sanitize()` function strips injection phrases
("ignore previous instructions", role markers, fences), neutralises `<finding>`
delimiter breakout, redacts secrets/paths/env/traces, and truncates. The fixed
system prompt is always first and tells the model to treat the delimited finding
strictly as data.

## Retry policy

Exponential back-off on transient failures (timeouts, connection errors, and
status `429/500/502/503/504`) up to `retry_count`. Auth failures (`401/403`) and
other `4xx` are **not** retried. Every failure becomes an `AIError` subtype
(`AITimeoutError`, `AIAuthenticationError`, `AIRateLimitError`, `AIResponseError`).

## Fail-safe

An AI failure raises `AIError`; the existing `StartAssessment` use case treats
enrichment as best-effort, so the finding is recorded unchanged and the scan
completes. **AI being down never fails a scan** (covered by an integration test).

## Configuration (`KINGSEC_AI__*`)

| Setting | Default | Meaning |
|---|---|---|
| `provider` | `anthropic` | provider name (selects the strategy) |
| `base_url` | provider default | override the provider endpoint base |
| `api_key` | `None` | `SecretStr`; BYO-key |
| `model` | `claude-sonnet-4-5` | model id |
| `request_timeout_seconds` | `30` | per-request timeout (the "timeout" control) |
| `temperature` | `0.2` | low → deterministic security guidance |
| `max_tokens` | `1024` | output cap |
| `retry_count` | `2` | transient-failure retries |
| `retry_delay` | `0.5` | base back-off seconds |
| `verify_ssl` | `true` | TLS verification (secure default) |

## Usage

```python
from kingsec.infrastructure.ai import register_ai
register_ai(app.container, app.settings)     # binds AIPort, adds client-close hook
```

## Testing

Unit tests use `httpx.MockTransport` (providers, prompt/injection, parser, client
retries/timeouts/auth/rate-limit/malformed, adapter, DI). Integration tests run a
real local HTTP server for the happy path, error/malformed translation, the full
scan→enrich→persist slice, and the AI-outage fail-safe.
