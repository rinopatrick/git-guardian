"""Configuration for Git Guardian."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # AI Analysis
    ai_base_url: str = "https://opengateway.gitlawb.com/v1/xiaomi-mimo"
    ai_model: str = "mimo-v2.5-pro"
    ai_enabled: bool = True

    # npm Registry
    npm_registry: str = "https://registry.npmjs.org"

    # Scanning
    max_file_size_mb: int = 10
    scan_timeout_seconds: int = 300
    max_depth: int = 10

    # Database
    database_url: str = "sqlite+aiosqlite:///./git_guardian.db"

    # Web Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    model_config = {"env_prefix": "GIT_GUARDIAN_"}


settings = Settings()
