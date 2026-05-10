# EVE

EVE, the Exploit Validation Engine, is an on-premises security platform for aggregating scanner findings and enriching them with vulnerability and exploit metadata.

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

## Local Development

The full development environment is specified in `SPECIFICATION.md`. Start with the backend smoke test and frontend build once dependencies are installed.

```bash
python -m pip install -e "backend[dev]"
pytest backend

cd frontend
npm install
npm run build
```
