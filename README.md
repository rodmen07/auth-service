# Auth Service (Python / FastAPI)

Authentication microservice that issues and verifies JWTs, enforces role-based access with admin-subject gating, and provides a Decap CMS GitHub OAuth popup provider.

## Features

| Area | Highlights |
|---|---|
| **JWT Issue / Verify** | `POST /auth/token` issues tokens; `POST /auth/verify` introspects them |
| **Role-Based Access** | Configurable allowed roles, privileged role gating by subject |
| **Admin Subject Gating** | Only subjects in `AUTH_ADMIN_SUBJECTS` may request privileged roles |
| **CMS GitHub OAuth** | Full popup OAuth flow for Decap CMS (`/cms/auth` → `/cms/callback`) |
| **Service Info** | `GET /info` exposes version and feature flags at runtime |
| **Health Check** | `GET /health` returns process liveness |
| **CORS** | Configurable origin allowlist via `AUTH_ALLOWED_ORIGINS` |

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 |
| Web framework | FastAPI 0.115.2 |
| Auth | PyJWT 2.9.0 |
| HTTP client | httpx 0.27.2 |
| Validation | Pydantic 2.9.2 |
| Server | Uvicorn 0.30.6 |
| Testing | pytest 8.3.3 |
| Deployment | Google Cloud Run (Docker) |

## Project Structure

```
app/
├── main.py          # FastAPI app, route definitions, middleware
├── jwt_utils.py     # JWT build/decode, config from env
├── models.py        # Pydantic request/response schemas
├── roles.py         # Role validation, admin subject gating
├── settings.py      # CORS origin config
└── cms_oauth.py     # GitHub OAuth popup flow (state, callbacks, HTML)
tests/
├── test_auth_api.py # Token issue/verify round-trip tests
└── test_cms_oauth.py# OAuth state signing/verification tests
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Process liveness |
| `GET` | `/info` | Service version and feature flags |
| `POST` | `/auth/token` | Issue JWT (`{ subject, roles }`) |
| `POST` | `/auth/verify` | Verify/introspect a JWT (`{ token }`) |
| `GET` | `/cms/auth` | Start Decap CMS GitHub OAuth popup flow |
| `GET` | `/cms/callback` | Complete OAuth flow, post result to opener |

### Examples

```bash
# Issue token
curl -X POST http://localhost:8082/auth/token \
  -H "Content-Type: application/json" \
  -d '{"subject":"demo-user","roles":["user"]}'

# Verify token
curl -X POST http://localhost:8082/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"<jwt>"}'

# Service info
curl http://localhost:8082/info
```

## Run Locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8082
```

## Test

```bash
PYTHONPATH=. pytest -q
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `AUTH_JWT_SECRET` | `dev-insecure-secret-change-me` | JWT signing secret (change in production) |
| `AUTH_JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `AUTH_TOKEN_EXPIRES_SECONDS` | `3600` | Token TTL in seconds |
| `AUTH_ISSUER` | `auth-service` | JWT issuer claim |
| `AUTH_ALLOWED_ORIGINS` | localhost + GitHub Pages | Comma-separated CORS origins |
| `AUTH_ALLOWED_ROLES` | `user,planner,admin` | Roles clients may request |
| `AUTH_PRIVILEGED_ROLES` | `admin` | Roles requiring admin subject |
| `AUTH_ADMIN_SUBJECTS` | *(empty)* | Subjects allowed privileged roles |
| `CMS_GITHUB_CLIENT_ID` | — | GitHub OAuth App client ID |
| `CMS_GITHUB_CLIENT_SECRET` | — | GitHub OAuth App client secret |
| `CMS_GITHUB_REDIRECT_URI` | auto-resolved | Must match GitHub OAuth callback URL |
| `CMS_GITHUB_SCOPE` | `repo` | Default OAuth scope |
| `CMS_OAUTH_STATE_TTL_SECONDS` | `600` | OAuth state expiry |
| `APP_PORT` | `8082` | Server port |

### Admin Role Gating

- Clients may only request roles in `AUTH_ALLOWED_ROLES`
- Roles in `AUTH_PRIVILEGED_ROLES` (e.g. `admin`) require the subject to be in `AUTH_ADMIN_SUBJECTS`
- Non-admin subjects requesting privileged roles receive `403`

## CMS OAuth Setup

1. Create a GitHub OAuth App
2. Set callback URL to your deployed auth service URL, for example:
  `https://auth-service-<project>.run.app/cms/callback`
3. Configure runtime secrets/env vars in your deployment target (`CMS_GITHUB_CLIENT_ID`, `CMS_GITHUB_CLIENT_SECRET`, `CMS_GITHUB_REDIRECT_URI`)
4. Deploy and use the CMS admin login
