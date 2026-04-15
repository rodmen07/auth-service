import hashlib
import logging
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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
    email: str | None = None


@dataclass
class InviteRecord:
    id: str
    email: str
    token: str
    expires_at: str
    used_at: str | None = None


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


_CREATE_INVITES = """
CREATE TABLE IF NOT EXISTS invites (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    token      TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
)
"""

_CREATE_REFRESH_TOKENS = """
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  TEXT UNIQUE NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT
)
"""

_CREATE_PASSWORD_RESET_TOKENS = """
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    token_hash  TEXT UNIQUE NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
)
"""


async def init_db(db_path: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute(_CREATE_USERS)
        await db.execute(_CREATE_OAUTH_IDENTITIES)
        await db.execute(_CREATE_INVITES)
        await db.execute(_CREATE_REFRESH_TOKENS)
        await db.execute(_CREATE_PASSWORD_RESET_TOKENS)
        # Migration: add roles column if missing
        cursor = await db.execute("PRAGMA table_info(users)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "roles" not in columns:
            await db.execute("ALTER TABLE users ADD COLUMN roles TEXT DEFAULT NULL")
        if "email" not in columns:
            await db.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT NULL")
            # Back-fill: for password-auth users, email == username (validated as email at registration)
            await db.execute("UPDATE users SET email = username WHERE email IS NULL AND password_hash IS NOT NULL")
        await db.commit()
    logger.info("Database initialised at %s", db_path)


async def create_user_with_password(db_path: str, username: str, password_hash: str) -> UserRecord:
    """Insert a new user. Raises ValueError('username_taken') if the username already exists."""
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "INSERT INTO users (id, username, password_hash, created_at, email) VALUES (?, ?, ?, ?, ?)",
                (user_id, username, password_hash, now, username),
            )
            await db.commit()
    except aiosqlite.IntegrityError:
        raise ValueError("username_taken")
    return UserRecord(id=user_id, username=username, password_hash=password_hash, created_at=now, email=username)


async def get_user_by_username(db_path: str, username: str) -> UserRecord | None:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT id, username, password_hash, created_at, roles, email FROM users WHERE username = ?",
            (username,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return UserRecord(id=row[0], username=row[1], password_hash=row[2], created_at=row[3], roles=row[4], email=row[5])


async def get_user_by_id(db_path: str, user_id: str) -> UserRecord | None:
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT id, username, password_hash, created_at, roles, email FROM users WHERE id = ?",
            (user_id,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return UserRecord(id=row[0], username=row[1], password_hash=row[2], created_at=row[3], roles=row[4], email=row[5])


async def get_user_by_email(db_path: str, email: str) -> UserRecord | None:
    """Look up a user by their canonical email address."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT id, username, password_hash, created_at, roles, email FROM users WHERE email = ?",
            (email,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return UserRecord(id=row[0], username=row[1], password_hash=row[2], created_at=row[3], roles=row[4], email=row[5])


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
    provider_email: str | None = None,
) -> tuple[UserRecord, bool]:
    """
    Look up an existing user by OAuth identity or email.
    If not found, create a new user (and associated OAuth identity).
    Returns (UserRecord, created: bool).

    Linking priority:
      1. Exact match on (provider, provider_user_id) — same OAuth identity
      2. Email match on users.email — links OAuth to an existing email/password account
      3. Create new user
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    async with aiosqlite.connect(db_path) as db:
        # 1. Look up existing OAuth identity
        async with db.execute(
            "SELECT user_id FROM oauth_identities WHERE provider = ? AND provider_user_id = ?",
            (provider, provider_user_id),
        ) as cursor:
            identity_row = await cursor.fetchone()

        if identity_row is not None:
            user_id = identity_row[0]
            async with db.execute(
                "SELECT id, username, password_hash, created_at, roles, email FROM users WHERE id = ?",
                (user_id,),
            ) as cursor:
                user_row = await cursor.fetchone()
            if user_row is None:
                raise RuntimeError(f"OAuth identity references missing user {user_id}")
            return (
                UserRecord(
                    id=user_row[0], username=user_row[1],
                    password_hash=user_row[2], created_at=user_row[3],
                    roles=user_row[4], email=user_row[5],
                ),
                False,
            )

        # 2. Email-based linking: find existing user by provider email
        if provider_email:
            async with db.execute(
                "SELECT id, username, password_hash, created_at, roles, email FROM users WHERE email = ?",
                (provider_email,),
            ) as cursor:
                existing_row = await cursor.fetchone()

            if existing_row is not None:
                user_id = existing_row[0]
                identity_id = str(uuid.uuid4())
                await db.execute(
                    "INSERT INTO oauth_identities (id, user_id, provider, provider_user_id, provider_username, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (identity_id, user_id, provider, provider_user_id, provider_username, now),
                )
                await db.commit()
                return (
                    UserRecord(
                        id=existing_row[0], username=existing_row[1],
                        password_hash=existing_row[2], created_at=existing_row[3],
                        roles=existing_row[4], email=existing_row[5],
                    ),
                    False,
                )

        # 3. No existing identity or email match — create a new user + identity
        # Derive a unique username from provider_username (append suffix if taken)
        base = _sanitize_username(provider_username) or f"{provider}_user"
        username = await _unique_username(db, base)

        user_id = str(uuid.uuid4())
        identity_id = str(uuid.uuid4())

        await db.execute(
            "INSERT INTO users (id, username, password_hash, created_at, email) VALUES (?, ?, NULL, ?, ?)",
            (user_id, username, now, provider_email),
        )
        await db.execute(
            "INSERT INTO oauth_identities (id, user_id, provider, provider_user_id, provider_username, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (identity_id, user_id, provider, provider_user_id, provider_username, now),
        )
        await db.commit()

    return (
        UserRecord(id=user_id, username=username, password_hash=None, created_at=now, email=provider_email),
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


# ---------------------------------------------------------------------------
# Invite management
# ---------------------------------------------------------------------------

_INVITE_EXPIRES_HOURS = int(os.getenv("INVITE_EXPIRES_HOURS", "72"))


async def create_invite(db_path: str, email: str) -> InviteRecord:
    """Create a new invite for the given email. Returns the InviteRecord with the raw token."""
    invite_id = str(uuid.uuid4())
    token = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=_INVITE_EXPIRES_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO invites (id, email, token, expires_at) VALUES (?, ?, ?, ?)",
            (invite_id, email.lower().strip(), token, expires_at),
        )
        await db.commit()
    return InviteRecord(id=invite_id, email=email.lower().strip(), token=token, expires_at=expires_at)


async def get_invite_by_token(db_path: str, token: str) -> InviteRecord | None:
    """Return the invite for the given token, or None if not found."""
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT id, email, token, expires_at, used_at FROM invites WHERE token = ?",
            (token,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return InviteRecord(id=row[0], email=row[1], token=row[2], expires_at=row[3], used_at=row[4])


async def mark_invite_used(db_path: str, token: str) -> bool:
    """Mark an invite as used. Returns True if the invite was found and updated."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "UPDATE invites SET used_at = ? WHERE token = ? AND used_at IS NULL",
            (now, token),
        )
        await db.commit()
        return cursor.rowcount > 0


def _is_expired(expires_at: str) -> bool:
    """Return True if the ISO 8601 UTC timestamp string is in the past."""
    try:
        expiry = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > expiry
    except ValueError:
        return True


# ---------------------------------------------------------------------------
# Refresh token management
# ---------------------------------------------------------------------------

_REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(7 * 24 * 3600)))


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def create_refresh_token(db_path: str, user_id: str) -> str:
    """Generate, store (hashed), and return a raw refresh token for the user."""
    raw = secrets.token_hex(32)
    token_hash = _hash_token(raw)
    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(seconds=_REFRESH_TOKEN_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
            (token_id, user_id, token_hash, expires_at),
        )
        await db.commit()
    return raw


async def validate_and_get_refresh_token_user(db_path: str, raw: str) -> UserRecord | None:
    """
    Validate a raw refresh token (hash it, look up, check expiry/revocation).
    Returns the associated UserRecord on success, None otherwise.
    """
    token_hash = _hash_token(raw)
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT user_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?",
            (token_hash,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    user_id, expires_at, revoked_at = row
    if revoked_at is not None or _is_expired(expires_at):
        return None
    return await get_user_by_id(db_path, user_id)


async def revoke_refresh_token(db_path: str, raw: str) -> bool:
    """Revoke a refresh token by its raw value. Returns True if found and revoked."""
    token_hash = _hash_token(raw)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (now, token_hash),
        )
        await db.commit()
        return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Password reset token management
# ---------------------------------------------------------------------------

_RESET_TOKEN_TTL_MINUTES = int(os.getenv("RESET_TOKEN_TTL_MINUTES", "60"))


async def create_password_reset_token(db_path: str, user_id: str) -> str:
    """Generate, store (hashed), and return a raw password reset token."""
    raw = secrets.token_hex(32)
    token_hash = _hash_token(raw)
    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(minutes=_RESET_TOKEN_TTL_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
            (token_id, user_id, token_hash, expires_at),
        )
        await db.commit()
    return raw


async def validate_and_get_reset_token_user(db_path: str, raw: str) -> UserRecord | None:
    """Validate a raw reset token. Returns the associated UserRecord on success, None otherwise."""
    token_hash = _hash_token(raw)
    async with aiosqlite.connect(db_path) as db:
        async with db.execute(
            "SELECT user_id, expires_at, used_at FROM password_reset_tokens WHERE token_hash = ?",
            (token_hash,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    user_id, expires_at, used_at = row
    if used_at is not None or _is_expired(expires_at):
        return None
    return await get_user_by_id(db_path, user_id)


async def mark_password_reset_used(db_path: str, raw: str) -> bool:
    """Mark a reset token as used. Returns True if found and updated."""
    token_hash = _hash_token(raw)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
            (now, token_hash),
        )
        await db.commit()
        return cursor.rowcount > 0


async def update_user_password(db_path: str, user_id: str, new_hash: str) -> bool:
    """Update the password hash for a user. Returns True if the user was found."""
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, user_id),
        )
        await db.commit()
        return cursor.rowcount > 0
