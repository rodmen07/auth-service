import re

from pydantic import BaseModel, Field, field_validator


class HealthResponse(BaseModel):
    status: str


class TokenRequest(BaseModel):
    subject: str = Field(min_length=3, max_length=120)
    roles: list[str] = Field(default_factory=list)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int


class VerifyRequest(BaseModel):
    token: str


class RevokeRequest(BaseModel):
    token: str


class VerifyResponse(BaseModel):
    active: bool
    subject: str | None = None
    roles: list[str] | None = None
    exp: int | None = None
    issuer: str | None = None


class JwtConfig(BaseModel):
    secret: str
    algorithm: str
    expires_seconds: int
    issuer: str
    private_key: str | None = None
    public_key: str | None = None


# ---------------------------------------------------------------------------
# User auth models
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


class RegisterRequest(BaseModel):
    username: str = Field(min_length=6, max_length=254)
    password: str = Field(min_length=6, max_length=128)

    @field_validator("username")
    @classmethod
    def username_chars(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("must be a valid email address")
        return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class AuthUserResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user_id: str
    username: str
    roles: list[str]
