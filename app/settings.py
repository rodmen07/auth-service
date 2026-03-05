import os

_DEFAULT_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://rodmen07.github.io",
]


def get_allowed_origins() -> list[str]:
    raw = os.getenv("AUTH_ALLOWED_ORIGINS", "").strip()

    if not raw:
        return _DEFAULT_ORIGINS

    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    # Fall back to the safe default list rather than opening up to '*'
    # when the env var is set but produces no valid entries after parsing.
    return origins if origins else _DEFAULT_ORIGINS
