# Auth Service (MVP Scaffold)

Authentication microservice scaffold for the microservices workspace.

## API

- `GET /health` -> `{ "status": "ok" }`
- `POST /auth/token`
  - Request: `{ "subject": "demo-user", "roles": ["user"] }`
  - Response: `{ "access_token": "...", "token_type": "bearer", "expires_in": 3600 }`
- `POST /auth/verify`
  - Request: `{ "token": "..." }`
  - Response (valid): `{ "active": true, "subject": "demo-user", "roles": ["user"], "exp": 123, "issuer": "auth-service" }`
  - Response (invalid): `{ "active": false }`
- `GET /cms/auth?provider=github&site_id=<host>[&scope=repo]`
  - Starts Decap CMS popup OAuth flow for GitHub
- `GET /cms/callback`
  - Completes OAuth flow and posts success/error to the Decap CMS opener window

## Run locally

```bash
cd /mnt/d/Projects/microservices/auth-service
python3 -m pip install --user -r requirements.txt
uvicorn app.main:app --reload --port 8082
```

## Test

```bash
cd /mnt/d/Projects/microservices/auth-service
PYTHONPATH=. python3 -m pytest -q
```

## Environment

- `AUTH_JWT_SECRET` (required in production)
- `AUTH_JWT_ALGORITHM` (default: `HS256`)
- `AUTH_TOKEN_EXPIRES_SECONDS` (default: `3600`)
- `AUTH_ISSUER` (default: `auth-service`)
- `AUTH_ALLOWED_ORIGINS` (comma-separated origins for browser clients)
- `AUTH_ALLOWED_ROLES` (default: `user,planner,admin`)
- `AUTH_PRIVILEGED_ROLES` (default: `admin`)
- `AUTH_ADMIN_SUBJECTS` (comma-separated subjects allowed to request privileged roles)
- `CMS_GITHUB_CLIENT_ID` (required for CMS GitHub login)
- `CMS_GITHUB_CLIENT_SECRET` (required for CMS GitHub login)
- `CMS_GITHUB_REDIRECT_URI` (recommended; must exactly match your GitHub OAuth app callback URL)
- `CMS_GITHUB_SCOPE` (default: `repo`)
- `CMS_OAUTH_STATE_TTL_SECONDS` (default: `600`)
- `APP_PORT` (default: `8082`)

### Admin role management

- Clients can only request roles listed in `AUTH_ALLOWED_ROLES`.
- Roles listed in `AUTH_PRIVILEGED_ROLES` (for example `admin`) require the token subject to be listed in `AUTH_ADMIN_SUBJECTS`.
- If a non-admin subject requests privileged roles, `/auth/token` returns `403`.

## CMS OAuth setup

1. Create a GitHub OAuth App.
2. Set Authorization callback URL to `https://auth-service-rodmen07-v2.fly.dev/cms/callback`.
3. Configure Fly secrets:

```bash
fly secrets set CMS_GITHUB_CLIENT_ID=<client_id> CMS_GITHUB_CLIENT_SECRET=<client_secret> CMS_GITHUB_REDIRECT_URI=https://auth-service-rodmen07-v2.fly.dev/cms/callback
```

4. Deploy auth-service.
5. Open the CMS admin URL and click GitHub login.

## MVP scope notes

- This scaffold issues/verifies JWTs for internal service integration work.
- It now also provides a minimal Decap CMS GitHub OAuth popup provider.
