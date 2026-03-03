# Auth Service Instructions (MVP)

## Service role

- Own token issuance and token verification for the microservices workspace.
- Keep auth logic isolated from business-domain services.

## API contract (MVP)

- GET /health -> { "status": "ok" }
- POST /auth/token
  - request: { subject: string, roles: string[] }
  - response: { access_token, token_type, expires_in }
- POST /auth/verify
  - request: { token: string }
  - response: { active: boolean, subject?, roles?, exp?, issuer? }

## Environment

- AUTH_JWT_SECRET
- AUTH_JWT_ALGORITHM (default HS256)
- AUTH_TOKEN_EXPIRES_SECONDS (default 3600)
- AUTH_ISSUER (default auth-service)

## Guardrails

- Preserve stable token response fields expected by downstream services.
- Validate and sanitize subject/roles payloads before signing.
- Do not add user-password persistence in this MVP scaffold unless explicitly requested.

## Quality gate

- Run `PYTHONPATH=. python3 -m pytest -q` before finalizing changes.
