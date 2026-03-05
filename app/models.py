from pydantic import BaseModel, Field


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
