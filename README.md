# EVE

EVE, the Exploit Validation Engine, is an on-premises security platform for aggregating scanner findings and enriching them with vulnerability and exploit metadata.

## Development Disclosure

This project is developed with the assistance of generative AI tools. AI assistance is used for drafting, implementation, review, and documentation support; project direction, acceptance, and responsibility for use remain with the human maintainer.

## Phase 1 Scope

- FastAPI backend
- Python 3.14 runtime
- React TypeScript frontend
- PostgreSQL primary datastore
- Redis for Celery, cache, token state, and rate-limit counters
- Nessus / Tenable.sc as the first scanner connector
- Metadata-only vulnerability enrichment and exploit intelligence

Phase 1 does not include exploit execution, execution credentials, or execution-related API/data-model scaffolding.

## Repository Layout

- `backend/` - FastAPI application, scanner connector interfaces, tests, and backend container definition
- `frontend/` - Vite React application and frontend container definition
- `helm/eve/` - Kubernetes deployment chart scaffold
- `docs/` - architecture notes, integration guides, runbooks, and legal drafts
- `.github/` - CI workflow and collaboration templates

## Current Backend Foundation

- Async SQLAlchemy engine/session helpers are available for FastAPI dependencies and tests.
- Alembic contains the baseline Phase 1 schema migration.
- Seed services initialize built-in roles plus NVD and SearchSploit metadata sources idempotently.
- A small repository primitive supports basic async model persistence.
- Local authentication primitives now cover password hashing, signed access tokens, and revocable refresh sessions.
- The first auth API endpoints support login, refresh-token rotation, logout, current-user lookup, secure browser cookies, and CSRF checks for cookie-authenticated state changes.

## Local Development

The full development environment is specified in `SPECIFICATION.md`. Start with the backend smoke test and frontend build once dependencies are installed.

```bash
python -m pip install -e "backend[dev]"
pytest backend

cd frontend
npm install
npm test -- --run
npm run build
```

For local auth testing without PostgreSQL, bootstrap a SQLite development database and
create the documented test admin account:

```bash
EVE_DATABASE_URL=sqlite+aiosqlite:///./eve-dev.sqlite3 \
  .venv/bin/python -m app.cli dev-bootstrap
```

Then start the API on port `8001`:

```bash
EVE_DATABASE_URL=sqlite+aiosqlite:///./eve-dev.sqlite3 \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Local test account:

```text
Email: admin@example.test
Password: correct-password
```

The frontend development server currently runs on port `8000`:

```bash
cd frontend
npm run dev -- --host 0.0.0.0
```

The first-pass dashboard UI is available during local development at:

```text
http://localhost:8000/?preview=dashboard
```
