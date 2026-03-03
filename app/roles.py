import os

from fastapi import HTTPException


DEFAULT_ALLOWED_ROLES = ["user", "planner", "admin"]
DEFAULT_PRIVILEGED_ROLES = ["admin"]


def _csv_env(name: str, default_values: list[str]) -> list[str]:
    raw = os.getenv(name, "")
    if not raw.strip():
        return default_values

    values = [item.strip().lower() for item in raw.split(",") if item.strip()]
    return values or default_values


def _csv_subjects(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def sanitize_roles(*, subject: str, requested_roles: list[str]) -> list[str]:
    allowed_roles = set(_csv_env("AUTH_ALLOWED_ROLES", DEFAULT_ALLOWED_ROLES))
    privileged_roles = set(_csv_env("AUTH_PRIVILEGED_ROLES", DEFAULT_PRIVILEGED_ROLES))
    admin_subjects = _csv_subjects("AUTH_ADMIN_SUBJECTS")

    normalized: list[str] = []
    seen: set[str] = set()
    for role in requested_roles:
        value = role.strip().lower()
        if not value:
            continue
        if value in allowed_roles:
            if value not in seen:
                normalized.append(value)
                seen.add(value)

    if not normalized:
        normalized = ["user"]

    requested_privileged = [role for role in normalized if role in privileged_roles]
    if requested_privileged and subject not in admin_subjects:
        raise HTTPException(status_code=403, detail="subject is not allowed to request privileged roles")

    return normalized
