# src/faramesh/server/settings.py
from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Core settings for Faramesh - minimal configuration."""
    model_config = SettingsConfigDict(env_prefix="FARA_", case_sensitive=False)

    # DB selection
    db_backend: str = "sqlite"

    # SQLite
    sqlite_path: str = "data/actions.db"

    # Postgres
    postgres_dsn: str = "postgres://user:password@localhost:5432/faramesh"

    # Policy file
    policy_file: str = "policies/default.yaml"

    # Auth
    auth_token: Optional[str] = None

    # API config (for CLI)
    api_base: str = "http://127.0.0.1:8000"
    api_host: Optional[str] = None
    api_port: Optional[int] = None

    # Action timeout (in seconds, must be positive)
    action_timeout: int = 300

    # Server config (from env, not FARA_ prefix)
    # These are read directly from os.getenv to avoid FARA_ prefix
    enable_cors: bool = False  # Set via FARAMESH_ENABLE_CORS=1

    def model_post_init(self, __context) -> None:
        """Build api_base from host/port if needed and validate settings."""
        # Validate action_timeout
        if self.action_timeout <= 0:
            import warnings
            warnings.warn(f"action_timeout must be positive, got {self.action_timeout}. Using default 300.")
            self.action_timeout = 300
        
        if self.api_host:
            # Defensive check for api_base
            if not self.api_base or not isinstance(self.api_base, str):
                self.api_base = "http://127.0.0.1:8000"
            if not self.api_base.startswith("http"):
                port = self.api_port or 8000
                self.api_base = f"http://{self.api_host}:{port}"


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
