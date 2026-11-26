# NetLog AI

[![NetLog AI CI](https://github.com/Chandu1133/netlog-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/Chandu1133/netlog-ai/actions/workflows/ci.yml)

**AI-powered network & server log analyzer, hybrid anomaly detector, and plain-English incident summarizer.**

NetLog AI ingests raw server logs (`syslog`, Nginx access logs, or structured JSON), detects security and reliability anomalies using modular rule-based detectors plus a scikit-learn `IsolationForest` model, redacts sensitive fields (partial IP masking, emails, JWTs, bearer tokens, and secrets), and calls a provider-agnostic LLM interface to generate structured incident summaries with a likely root cause and suggested fix.

Everything runs locally via `docker compose up` with **zero API key required** (powered by `MockLLMClient` by default).

---

## Key Features

- **Resilient Log Ingestion**: `POST /logs/upload` (`.log`/`.txt` in RFC 3164/ISO syslog and Nginx combined/extended access-log formats) and `POST /logs` (JSON batch). Malformed lines are counted and sampled without crashing ingestion.
- **Hybrid Anomaly Detection**:
  - **Rule-based**: SSH/auth failed-login spikes per IP, HTTP 5xx error-rate spikes per host/service, and repeated canonicalized error bursts.
  - **ML-based**: `IsolationForest` trained on a baseline window of per-minute features (`request_count`, `error_rate`, `mean_latency_ms`, `p95_latency_ms`).
- **Safe, Validated AI Summaries**:
  - Never sends full raw logs to an LLM—only aggregated evidence and up to 5 redacted sample lines.
  - Strict Pydantic v2 output validation (`title`, `summary`, `likely_root_cause`, `suggested_fix`, `confidence`), automatic single retry on invalid JSON, and deterministic template fallback on provider failure.
- **Production Guardrails**: MySQL 8 + SQLAlchemy 2.0 ORM (parameterized queries only) + Alembic migrations, `X-API-Key` authentication on all write endpoints, upload size limit, per-IP sliding-window upload rate limiting, structured logging, and OpenAPI docs at `/docs`.
- **Operational Dashboard**: Single-page HTML/CSS/JS dashboard served at `/` featuring Chart.js error/latency timelines with anomaly highlights, severity badges, incident detail inspector, quick log upload, and 30-second auto-refresh.

---

## Architecture Overview

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full component and sequence diagrams.

```text
Log Sources (Syslog / Nginx / JSON)
        │  POST /logs/upload | POST /logs (X-API-Key + Rate Limit)
        ▼
  Parser & Ingestion Layer ──► MySQL 8 (log_entries)
        │
        ▼
  Hybrid Anomaly Engine (Rules + IsolationForest)
        │
        ▼
  Incident Grouper ──► PII/Secret Redactor ──► LLM Layer (Mock / OpenAI)
                                                      │  (Pydantic + Retry + Fallback)
                                                      ▼
                                        MySQL 8 (anomalies, incidents)
                                                      │
                                                      ▼
                              FastAPI Read API (/incidents, /anomalies, /stats)
                                                      │
                                                      ▼
                              Single-Page Dashboard (/) + OpenAPI (/docs)
```

---

## Quick Start (Docker Compose — No API Key Required)

```bash
git clone <your-repo-url>
cd netlog-ai
docker compose up --build
```

Services started:
- **Dashboard**: `http://localhost:8000/`
- **Interactive OpenAPI Docs**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/health`
- **MySQL 8**: `localhost:3306`

Default local compose `X-API-Key` is `netlog-local-dev-key` (override via `.env` — see `.env.example`).

### Quick Start Without Docker (Local Python + SQLite)

```bash
cd netlog-ai
cp .env.example .env
# Set DATABASE_URL=sqlite:///./netlog_ai.db, API_KEY=my-local-dev-key, LLM_PROVIDER=mock in .env
pip install -r requirements.txt
python -m alembic upgrade head
python -m uvicorn app.main:app --reload --port 8000
```

### Switch to a Real OpenAI-Compatible Provider (Optional)

Copy `.env.example` to `.env` and set:

```env
LLM_PROVIDER=openai
LLM_API_KEY=your-provider-api-key
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

---

## API Examples

### 1. Health Check

```bash
curl -s http://localhost:8000/health | jq
```

### 2. Upload a Log File (Syslog / Nginx)

```bash
python scripts/generate_logs.py --output-dir data --duration-minutes 90 --seed 42

curl -s -X POST "http://localhost:8000/logs/upload?run_analysis=true" \
  -H "X-API-Key: netlog-local-dev-key" \
  -F "file=@data/synthetic_server.log" | jq
```

### 3. Ingest a JSON Batch

```bash
curl -s -X POST "http://localhost:8000/logs" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: netlog-local-dev-key" \
  -d '{
    "run_analysis": true,
    "logs": [
      {
        "timestamp": "2026-11-24T15:00:00Z",
        "host": "edge-01",
        "source_ip": "192.0.2.10",
        "service": "nginx",
        "level": "ERROR",
        "status_code": 502,
        "latency_ms": 845.2,
        "message": "POST /api/checkout HTTP/1.1 -> HTTP 502"
      }
    ]
  }' | jq
```

### 4. Query Incidents, Anomalies, and Time-Series Stats

```bash
# Paginated high-severity incidents
curl -s "http://localhost:8000/incidents?severity=high&limit=10&offset=0" | jq

# Single incident with linked anomalies & AI summary
curl -s "http://localhost:8000/incidents/1" | jq

# Detected anomalies filtered by type
curl -s "http://localhost:8000/anomalies?anomaly_type=ml_traffic_anomaly" | jq

# Aggregate metrics + per-minute chart time series
curl -s "http://localhost:8000/stats" | jq
```

---

## Evaluation Results

Measured directly via `python scripts/evaluate.py` against a 90-minute synthetic multi-host dataset (`5,357` log lines including `20` corrupted lines and `6` injected ground-truth incidents across SSH brute force, HTTP 5xx spikes, latency degradation, and repeated DB errors). Full breakdown in [docs/RESULTS.md](docs/RESULTS.md):

| Metric | Measured Value |
| --- | ---: |
| Precision / Recall / F1 | **1.0000 / 1.0000 / 1.0000** (6 TP, 0 FP, 0 FN) |
| Malformed Lines Safely Handled | **20 / 20** (0 crashes) |
| Parsing & Normalization Throughput | **15,303.2 lines/sec** |
| End-to-End Ingestion Throughput (Parse + DB Write) | **3,569.6 lines/sec** |
| Average Detection + Summary Latency (5 runs, MockLLM) | **891.49 ms** (0.34 ms/incident summary) |
| Automated Test Suite & Coverage | **32/32 passing · 90.12% coverage** |

---

## Dashboard Screenshots

> *Placeholders — capture screenshots after running `docker compose up` and uploading `data/synthetic_server.log`.*

- ![Dashboard Overview — KPIs and Error/Latency Timeline](docs/screenshots/dashboard-overview.png)
- ![Incident Detail — AI Root Cause, Suggested Fix, and Redacted Evidence](docs/screenshots/incident-detail.png)

---

## Local Development & Running Tests

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run linter and formatter checks
ruff check app scripts tests
black --check app scripts tests

# Run full test suite with coverage report
pytest --cov=app --cov-report=term-missing --cov-fail-under=80

# Run synthetic benchmark and regenerate docs/RESULTS.md
python scripts/generate_logs.py --output-dir data --duration-minutes 90 --seed 42
python scripts/evaluate.py --log-file data/synthetic_server.log --ground-truth data/ground_truth.json --results-file docs/RESULTS.md
```

---

## Deployment

See [docs/DEPLOY.md](docs/DEPLOY.md) for step-by-step instructions to deploy NetLog AI on an **AWS EC2 Free Tier** instance with Docker Compose and optional HTTPS via Nginx + Certbot.
