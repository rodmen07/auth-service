import os


def get_allowed_origins() -> list[str]:
    raw = os.getenv(
        "AUTH_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,https://rodmen07.github.io",
    )

    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["*"]
