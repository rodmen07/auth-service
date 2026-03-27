import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import aiosqlite
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger(__name__)

_ph = PasswordHasher()

_DEFAULT_DB_PATH = "auth.db"


def get_db_path() -> str:
    raw = os.getenv("DATABASE_URL", "").strip()
    if raw.startswith("sqlite:///"):
        return raw[len("sqlite:///"):]
    if raw.startswith("sqlite://"):
        return raw[len("sqlite://"):]
    return _DEFAULT_DB_PATH


def hash_password(plain: str) -> str:
    """Return an argon2id hash of *plain*. Never store the plain-text password."""
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches *hashed*. Never raises — returns False on any mismatch."""
    try:
        return _ph.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@dataclass
class UserRecord:
    id: str
    username: str
    password_hash: str | None
    created_at: str
    roles: str | None = None


_CREATE_USERS = """
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    created_at  TEXT NOT NULL
)
"""

_CREATE_OAUTH_IDENTITIES = """
CREATE TABLE IF NOT EXISTS oauth_identities (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id),
    provider         TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_username TEXT,
    created_at       TEXT NOT NULL,
    UNIQUE(provider, provider_user_id)
)
"""


async def init_db(db_path: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(_CREATE_USERS)
        await db.execute(_CREATE_OAUTH_IDENTITIES)
        # Migration: add roles column if missing
        cursor = await db.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "roles" not in columns:
            await db.execute("ALTER TABLE users ADD COLUMN roles TEXT DEFAULT NULL")
        await db.commit()
    logger.info("Database initialised at %s", db_path)


async def create_user_with_password(db_path: str, username: str, password_hash: str) -> UserRecord:
    """Insert a new user. Raises ValueError('username_taken') if the username already exists."""
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (user_id, username, password_hash, now),
            )
            await db.commit()
    except aiosqlite.IntegrityError:
        raise ValueError("username_taken")
    return UserRecord(id=user_id, username=username, password_hash=password_hash, created_at=now)


async def get_user_by_username(db_path: str, username: str) -> UserRecord | None:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT id, username, password_hash, created_at, roles FROM users WHERE username = ?",
            (username,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return UserRecord(id=row[0], username=row[1], password_hash=row[2], created_at=row[3], roles=row[4])


async def get_user_by_id(db_path: str, user_id: str) -> UserRecord | None:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT id, username, password_hash, created_at, roles FROM users WHERE id = ?",
            (user_id,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return UserRecord(id=row[0], username=row[1], password_hash=row[2], created_at=row[3], roles=row[4])


async def update_user_roles(db_path: str, user_id: str, roles: list[str]) -> bool:
    """Update the roles JSON column for a user. Returns True if the user was found."""
    import json
    roles_json = json.dumps(roles)
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "UPDATE users SET roles = ? WHERE id = ?",
            (roles_json, user_id),
        )
        await db.commit()
        return cursor.rowcount > 0


async def create_or_get_oauth_user(
    db_path: str,
    provider: str,
    provider_user_id: str,
    provider_username: str,
) -> tuple[UserRecord, bool]:
    """
    Look up an existing user by OAuth identity.
    If not found, create a new user (and associated OAuth identity).
    Returns (UserRecord, created: bool).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    async with aiosqlite.connect(db_path) as db:
        # Look up existing OAuth identity
        async with db.execute(
            "SELECT user_id FROM oauth_identities WHERE provider = ? AND provider_user_id = ?",
            (provider, provider_user_id),
        ) as cursor:
            identity_row = await cursor.fetchone()

        if identity_row is not None:
            user_id = identity_row[0]
            async with db.execute(
                "SELECT id, username, password_hash, created_at, roles FROM users WHERE id = ?",
                (user_id,),
            ) as cursor:
                user_row = await cursor.fetchone()
            if user_row is None:
                raise RuntimeError(f"OAuth identity references missing user {user_id}")
            return (
                UserRecord(
                    id=user_row[0], username=user_row[1],
                    password_hash=user_row[2], created_at=user_row[3],
                    roles=user_row[4],
                ),
                False,
            )

        # No existing identity — create a new user + identity
        # Derive a unique username from provider_username (append suffix if taken)
        base = _sanitize_username(provider_username) or f"{provider}_user"
        username = await _unique_username(db, base)

        user_id = str(uuid.uuid4())
        identity_id = str(uuid.uuid4())

        await db.execute(
            "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, NULL, ?)",
            (user_id, username, now),
        )
        await db.execute(
            "INSERT INTO oauth_identities (id, user_id, provider, provider_user_id, provider_username, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (identity_id, user_id, provider, provider_user_id, provider_username, now),
        )
        await db.commit()

    return (
        UserRecord(id=user_id, username=username, password_hash=None, created_at=now),
        True,
    )


def _sanitize_username(raw: str) -> str:
    """Keep only alphanumeric, underscore, hyphen characters. Truncate to 40 chars."""
    sanitized = "".join(c for c in raw if c.isalnum() or c in ("_", "-"))
    return sanitized[:40]


async def _unique_username(db: aiosqlite.Connection, base: str) -> str:
    """Return *base* if available, otherwise *base_2*, *base_3*, etc."""
    candidate = base
    suffix = 2
    while True:
        async with db.execute("SELECT 1 FROM users WHERE username = ?", (candidate,)) as cursor:
            taken = await cursor.fetchone()
        if taken is None:
            return candidate
        candidate = f"{base}_{suffix}"
        suffix += 1
