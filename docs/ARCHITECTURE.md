# NetLog AI — System Architecture

## High-Level Overview

NetLog AI is a modular, production-style observability backend that ingests raw network and server
logs (syslog, Nginx access logs, or structured JSON), detects anomalies using a hybrid rule + ML
engine, redacts sensitive fields before calling a provider-agnostic LLM layer, and exposes both a
REST API and an auto-refreshing operational dashboard.

```mermaid
flowchart LR
    Sources["Log Sources\n(Syslog / Nginx / JSON)"] -->|POST /logs/upload\nPOST /logs\nX-API-Key + Rate Limit| Ingestion["Ingestion Service\n(Parsers + Validation)"]
    Ingestion -->|Parameterized ORM Inserts| MySQL[("MySQL 8\nlog_entries / anomalies / incidents")]
    Ingestion -->|Normalized Records| Rules["Rule Detectors\n• Failed Login Spike\n• HTTP 5xx Spike\n• Repeated Errors"]
    Ingestion -->|Per-Minute Features| ML["ML Detector\n(StandardScaler +\nIsolationForest)"]
    Rules --> Grouper["Incident Grouper\n(Host + Service + Window)"]
    ML --> Grouper
    Grouper --> Redactor["PII & Secret Redactor\n(Partial IP, Email, JWT, Tokens)"]
    Redactor -->|Compact Evidence +\n<=5 Redacted Lines| LLM["LLM Layer\n(MockLLM / OpenAI-Compatible)\nPydantic Validation + 1 Retry\n+ Template Fallback"]
    LLM --> MySQL
    MySQL --> API["FastAPI Read API\n/incidents /anomalies\n/stats /health /docs"]
    API --> Dashboard["Single-Page Dashboard\n(HTML/JS + Chart.js\n30s Auto-Refresh)"]
```

## Request & Incident Summarization Sequence

```mermaid
sequenceDiagram
    participant Client as Client / Log Shipper
    participant API as FastAPI (/logs/upload)
    participant Parser as Parsers (Syslog/Nginx)
    participant Det as Detectors (Rules + ML)
    participant Red as Redaction Service
    participant LLM as LLM Client (Mock / OpenAI)
    participant DB as MySQL 8 (SQLAlchemy 2.0)

    Client->>API: POST /logs/upload (X-API-Key, .log/.txt)
    API->>API: Check API Key, Rate Limit, File Size & Extension
    API->>Parser: Auto-detect & normalize lines (count bad lines)
    Parser-->>API: NormalizedLogRecord[] + bad_line_count
    API->>DB: Bulk insert LogEntry rows
    API->>Det: Run rule detectors + IsolationForest
    Det-->>API: DetectedAnomaly[]
    API->>API: Group overlapping anomalies by (host, service)
    loop Per Incident Group
        API->>Red: Mask IPs, emails, tokens, secrets
        Red-->>API: Redacted evidence + <=5 redacted samples
        API->>LLM: Compact JSON prompt
        LLM-->>API: Structured JSON (title, summary, root_cause, fix, confidence)
        alt Invalid JSON or Pydantic validation failure
            API->>LLM: Retry once with validation error feedback
            alt Retry fails or transport error
                API->>API: Deterministic template fallback (used_fallback=true)
            end
        end
        API->>DB: Persist Incident + linked Anomaly rows
    end
    API-->>Client: 201 Created (IngestionResponse)
```

## Module Breakdown

| Module | Responsibility |
| --- | --- |
| `app/config.py` | Environment-driven `pydantic-settings` configuration; zero secrets in code. |
| `app/database.py` & `app/models.py` | SQLAlchemy 2.0 ORM (`LogEntry`, `Anomaly`, `Incident`) with composite time-series indexes and Alembic migrations (`alembic/`). |
| `app/parsers/` | `BaseParser`, `SyslogParser` (RFC 3164 + ISO-8601), `NginxParser` (combined + extended latency/host/service), and auto-detection with safe bad-line accounting. |
| `app/detectors/` | Modular rule detectors (`FailedLoginSpikeDetector`, `Http5xxSpikeDetector`, `RepeatedErrorDetector`) and `IsolationForestDetector` fitted on baseline per-minute telemetry (`request_count`, `error_rate`, `mean_latency_ms`, `p95_latency_ms`). |
| `app/services/redaction.py` | Masks IPv4/IPv6 host octets (`203.0.xxx.xxx`), emails, JWTs, Bearer tokens, API keys, and key-value secrets before LLM prompts or anomaly storage. |
| `app/llm/` | Provider-agnostic `BaseLLMClient`, zero-key `MockLLMClient`, `OpenAICompatibleLLMClient`, compact prompt builders, Pydantic v2 validation, single retry, and template fallback. |
| `app/services/incidents.py` | Anomaly grouping, deduplication, AI summarization persistence, paginated filtering, and per-minute chart aggregation. |
| `app/api/` | FastAPI routers for health, ingestion, incidents, anomalies, stats, and on-demand analysis with `X-API-Key` auth and sliding-window upload rate limiting. |
| `app/static/` | Dependency-free single-page HTML/CSS/JS dashboard with Chart.js dual-axis error/latency charts and 30-second auto-refresh. |

## Security & Reliability Guardrails

- **Parameterized queries only**: All database access uses SQLAlchemy 2.0 ORM expressions and bound parameters.
- **Write protection**: `POST /logs/upload`, `POST /logs`, `POST /analyze`, and `PATCH /incidents/{id}/status` enforce constant-time `X-API-Key` validation.
- **Abuse controls**: Upload size is capped (`MAX_UPLOAD_SIZE_BYTES`), extensions are restricted (`.log`, `.txt`), and `/logs/upload` enforces per-client sliding-window rate limits (`429 Too Many Requests` + `Retry-After`).
- **Privacy boundary**: Full raw log payloads are never sent to external LLMs; only aggregated counts/metrics and up to 5 redacted lines cross the LLM boundary.
- **Graceful degradation**: Malformed log lines never abort ingestion; LLM failures or malformed JSON fall back deterministically to a template incident summary.
