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
- `APP_PORT` (default: `8082`)

## MVP scope notes

- This scaffold issues and verifies JWTs for internal service integration work.
- It intentionally does not include user/password storage or OAuth providers yet.
- Next production step is integrating token validation middleware into `backend-service` and route-level auth policies.
