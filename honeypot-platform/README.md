# Honeypot Analysis Platform

A full-stack honeypot and attacker behavior analysis stack: SSH and HTTP deception surfaces, structured logging, SQLite storage with optional Elasticsearch export, analytics, alerting (email / Slack / webhook), PDF JSON threat reports, and a React dashboard with live WebSocket updates.

```
┌─────────────┐     ┌─────────────┐
│ SSH :2222   │     │ HTTP :8080  │
│ (asyncssh)  │     │ (aiohttp)   │
└──────┬──────┘     └──────┬──────┘
       │ JSON logs          │
       └─────────┬──────────┘
                 ▼
         ┌───────────────┐
         │   pipeline    │ ingest → enrich (GeoIP) → SQLite
         └───────┬───────┘
                 │
     ┌───────────┼───────────┐
     ▼           ▼           ▼
┌─────────┐ ┌─────────┐ ┌─────────┐
│analytics│ │alerting │ │ FastAPI │
│scheduler│ │ engine  │ │  :8000  │
└─────────┘ └────┬────┘ └────┬────┘
                 │          │
                 │     ┌────┴────┐
                 │     │dashboard│ nginx :3000
                 └────►│reports  │
                       └─────────┘
```

## Quick Start (three commands)

From the repository root (`honeypot-platform/`):

```bash
cp .env.example .env
# Optional: place MaxMind GeoLite2-City.mmdb under ./data/ (see below)
docker compose up -d --build
docker compose exec api python scripts/seed_demo_data.py
```

Dashboard: **http://localhost:3000** — default credentials from `.env` (`ADMIN_USERNAME` / `ADMIN_PASSWORD`).

## What each service does

| Service | Role |
|---------|------|
| **ssh-honeypot** | Accepts SSH on `SSH_HONEYPOT_PORT`; fake Debian shell; writes JSON audit lines to `./logs`. |
| **http-honeypot** | Serves deceptive pages (`/login`, `/admin`, `.env`, etc.); fingerprints scanners; writes JSON logs. |
| **pipeline** | Tails log files, normalizes rows, GeoIP/asn enrichment, persists to SQLite and optional alert evaluation hooks. |
| **api** | FastAPI REST + JWT + WebSocket live feed backed by SQLite. |
| **dashboard** | Vite/React UI proxied via nginx to the API (`/api`, `/ws`). |

## GeoLite2 database (GeoIP)

1. Create a free account at [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).
2. Download **GeoLite2 City** as MMDB format.
3. Save as `./data/GeoLite2-City.mmdb` (path matches `GEOIP_DB_PATH`).

Without the file, enrichment falls back gracefully (country/city may be blank).

## Configuring alerting

In `.env` set:

- Email: `ALERT_EMAIL_ENABLED=true` and SMTP variables; `ALERT_MIN_SEVERITY_EMAIL` gates noise.
- Slack: `ALERT_SLACK_ENABLED=true` and `ALERT_SLACK_WEBHOOK_URL`.
- Generic webhook: `ALERT_WEBHOOK_ENABLED=true` and `ALERT_WEBHOOK_URL`.

Optional: `ABUSEIPDB_API_KEY` feeds reputation checks in analytics/alerting when set.

## Generating threat reports

- **API:** `POST /api/reports/generate` with body `{"period_days": 7}` (requires auth). Then `GET /api/reports` and download via `GET /api/reports/{id}/download` (PDF) or inspect JSON paths from list response.
- **CLI inside container:** `python -m analytics.scheduler` runs on interval; reporters live under `analytics/reporter.py`.

Reports are stored under `./reports/` as configured by `REPORTS_DIR`.

## Legal & ethical disclaimer

Deploy honeypots only on networks and systems **you own or are expressly authorized** to instrument. Unauthorized deployment may violate computer misuse laws and terms of service. This software is provided for defensive research and lab use; operators are solely responsible for compliance.

## Running tests

With compose stack bringing up volumes, prefer:

```bash
docker compose run --rm --no-deps api pytest /app/tests -v --tb=short
```

Or install Python 3.11+ locally, create a venv, `pip install -r api/requirements.txt` plus test deps from `requirements-test.txt`, set `DATABASE_URL` to a temp SQLite file, then `pytest tests/`.

## Optional ELK export

```bash
# After events exist in SQLite / logs pipeline
pip install elasticsearch requests python-dotenv
python scripts/export_to_elk.py
```

Uses `ELASTICSEARCH_URL` and `ELASTICSEARCH_INDEX` from `.env`.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Empty dashboard | Run seed script; confirm pipeline logs show ingest; SQLite volume mounted at `/app/data`. |
| 401 on API | Token expiry (1h access); refresh or re-login; `ADMIN_PASSWORD` matches `.env`. |
| WebSocket quiet | Firewall/proxy stripping `/ws`; nginx must Upgrade headers; pipeline must be writing events. |
| GeoIP always empty | `GEOIP_DB_PATH` correct inside container; file mounted into `./data`. |
| PDF missing charts | Ensure matplotlib backend `Agg` in container; `reports/` writable. |

## Acknowledgements

Design inspiration from [Cowrie](https://github.com/cowrie/cowrie) (SSH telnet honeypot) and [Glastopf](https://github.com/mushorg/glastopf) / modern web honeypot research. Built with `asyncssh`, `aiohttp`, FastAPI, SQLAlchemy 2, and ReportLab.

## Makefile targets

- `make up` / `make down` — compose lifecycle  
- `make logs` — follow all service logs  
- `make seed` — demo data (requires running `api` container)  
- `make test` — pytest in API container  
