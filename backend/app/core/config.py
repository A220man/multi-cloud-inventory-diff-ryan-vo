"""Application configuration settings."""
from typing import Literal, Optional
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    ENVIRONMENT: str = Field(default="development", description="Environment: development, test, production")
    PORT: int = Field(default=8000, description="Backend HTTP server port")
    HOST: str = Field(default="127.0.0.1", description="Backend HTTP server host")
    DATABASE_URL: str = Field(default="sqlite:///./inventory.db", description="Database connection URL")

    # Local Demo Mode configuration
    DEMO_MODE: bool = Field(default=False, description="Local-only demo mode with localhost mock auth")

    # OIDC Configuration
    OIDC_ISSUER_URL: str = Field(
        default="http://127.0.0.1:8080/realms/cloud-inventory",
        description="Keycloak OIDC realm issuer URL"
    )
    OIDC_CLIENT_ID: str = Field(default="cloud-inventory-client", description="OIDC client ID")
    OIDC_AUDIENCE: str = Field(default="cloud-inventory-client", description="Expected token audience")
    OIDC_JWKS_URI: Optional[str] = Field(
        default="http://127.0.0.1:8080/realms/cloud-inventory/protocol/openid-connect/certs",
        description="OIDC JSON Web Key Set URI"
    )

    # LLM Provider Configuration
    LLM_PROVIDER: Literal["openai-compatible", "anthropic", "gemini", "ollama"] = Field(
        default="openai-compatible",
        description="LLM Provider adapter"
    )
    LLM_MODEL: str = Field(default="gpt-4o-mini", description="Target model name")
    LLM_BASE_URL: str = Field(default="https://api.openai.com/v1", description="Provider API base URL")
    LLM_API_KEY: Optional[str] = Field(default=None, description="Operator API Key for LLM advisory")
    LLM_TIMEOUT_SECONDS: float = Field(default=15.0, description="HTTP timeout for LLM calls")

    @field_validator("DEMO_MODE")
    @classmethod
    def validate_demo_mode_safety(cls, v: bool, info) -> bool:
        env = info.data.get("ENVIRONMENT", "development")
        if env.lower() == "production" and v:
            raise ValueError("DEMO_MODE must NEVER be enabled in production environments.")
        return v

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
