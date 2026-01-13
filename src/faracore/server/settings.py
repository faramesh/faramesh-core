# src/faracore/server/settings.py
from __future__ import annotations

import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Core settings for FaraCore - minimal configuration."""
    model_config = SettingsConfigDict(env_prefix="FARA_", case_sensitive=False)

    # DB selection
    db_backend: str = "sqlite"

    # SQLite
    sqlite_path: str = "data/actions.db"

    # Postgres
    postgres_dsn: str = "postgres://postgres:postgres@localhost:5432/faracore"

    # Policy file
    policy_file: str = "policies/default.yaml"

    # Auth
    auth_token: Optional[str] = None

    # API config (for CLI)
    api_base: str = "http://127.0.0.1:8000"
    api_host: Optional[str] = None
    api_port: Optional[int] = None

    # Action timeout
    action_timeout: int = 300

    # Server config (from env, not FARA_ prefix)
    # These are read directly from os.getenv to avoid FARA_ prefix
    enable_cors: bool = False  # Set via FARACORE_ENABLE_CORS=1

    def model_post_init(self, __context) -> None:
        """Build api_base from host/port if needed."""
        if self.api_host and not self.api_base.startswith("http"):
            port = self.api_port or 8000
            self.api_base = f"http://{self.api_host}:{port}"


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
