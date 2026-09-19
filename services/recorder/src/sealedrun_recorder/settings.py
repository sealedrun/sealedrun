from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SEALEDRUN_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    database_url: str | None = None
    ui_dir: Path | None = None
    host: str = "0.0.0.0"  # noqa: S104
    port: int = 8080
    max_bundle_bytes: int = 256 * 1024 * 1024

    @property
    def resolved_database_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'sealedrun.db'}"


def load_settings() -> Settings:
    return Settings()
