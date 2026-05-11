![CI](https://github.com/davidmcduffie001/EVE/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.14-blue)
![Backend](https://img.shields.io/badge/backend-FastAPI-009688)
![Frontend](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61dafb)
![License](https://img.shields.io/badge/license-proprietary-lightgrey)

# EVE

EVE, the Exploit Validation Engine, is a self-hosted security operations platform for aggregating authorized scanner findings, normalizing vulnerability data, and enriching findings with metadata-only exploit intelligence.

EVE is being built for defensive vulnerability validation workflows. It does not execute exploits, store exploit execution credentials, or provide exploit-running APIs.

## Features

- Authenticated web UI for scanner finding review and account management
- Local authentication with secure browser cookies, refresh-session revocation, and CSRF protection
- Role-based access control with built-in and custom roles
- Tamper-evident audit logging for authentication and administrative events
- User profile, password, MFA status, preference, and theme controls
- SSO configuration foundation with validated OIDC browser login and SAML service-provider metadata
- PostgreSQL-backed FastAPI service layer with Alembic migrations
- React and Vite frontend with dark/light theme support
- Scanner connector foundation for Nessus and OpenVAS/Greenbone GMP endpoints
- Planned vulnerability and exploit metadata ingestion from non-execution intelligence sources

## Repository Layout

- `backend/` - FastAPI application, persistence models, services, API routes, tests, and backend packaging
- `frontend/` - Vite React application, UI assets, styles, and frontend tests
- `helm/eve/` - Kubernetes deployment chart scaffold
- `docs/` - architecture notes, integration guides, runbooks, and legal drafts
- `.github/` - CI workflow and GitHub collaboration templates

## Requirements

- Python 3.14
- Node.js and npm
- PostgreSQL for production-like deployments
- Redis for queued work, token state, cache, and rate-limit counters in the broader deployment architecture

The local development bootstrap can use SQLite for fast backend and UI iteration.

## Local Development

Install backend dependencies:

```bash
python -m pip install -e "backend[dev]"
```

Run backend tests:

```bash
pytest backend
```

Bootstrap the local development database:

```bash
EVE_DATABASE_URL=sqlite+aiosqlite:///./eve-dev.sqlite3 \
  .venv/bin/python -m app.cli dev-bootstrap
```

Start the API on port `8001`:

```bash
EVE_DATABASE_URL=sqlite+aiosqlite:///./eve-dev.sqlite3 \
  .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Install frontend dependencies:

```bash
cd frontend
npm install
```

Run frontend checks:

```bash
npm test -- --run
npm run build
```

Start the frontend development server on port `8000`:

```bash
npm run dev -- --host 0.0.0.0 --port 8000
```

Open the web UI at:

```text
http://localhost:8000
```

Local development account:

```text
Email: admin@example.test
Password: correct-password
```

For frontend-only preview work without a backend session, use:

```text
http://localhost:8000/?preview=dashboard
```

## Testing

Backend:

```bash
pytest backend
```

Frontend:

```bash
cd frontend
npm test -- --run
npm run lint
npm run build
```

## Security Scope

EVE is intended for authorized defensive security workflows only. Scanner integrations and vulnerability intelligence features should be used only against systems where the operator has explicit permission to assess and manage findings.

## Development Disclosure

This project is developed with the assistance of generative AI tools. AI assistance may be used for drafting, implementation, review, and documentation support. Project direction, acceptance decisions, and responsibility for use remain with the human maintainer.

## License & Copyright

Copyright (C) 2026 David McDuffie. All rights reserved.

No open-source license has been granted unless a separate `LICENSE` file or written agreement states otherwise.
