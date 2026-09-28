"""Recorder configuration read from SEALEDRUN_* environment variables and .env."""

from __future__ import annotations

from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Recorder settings; each field is set by the SEALEDRUN_-prefixed variable of the same name.

    Attributes:
        allowed_hosts: Host headers the recorder answers to; anything else is a DNS-rebinding
            attempt or a proxy that was not configured.
            Env form: SEALEDRUN_ALLOWED_HOSTS='["recorder.example.com"]'.
        trusted_principals: Principal ids obtained out of band (SPEC 13.2). When set, bundles
            from any other Principal are refused; when empty, everything consistent is stored
            and reported as not authenticated.
            Env form: SEALEDRUN_TRUSTED_PRINCIPALS='["qJtR..."]'.
        upstreams_file: YAML file with the model providers the LLM proxy forwards to.
        proxy_run_idle_seconds: Proxy calls without an X-SealedRun-Run header join the current
            run until it has been idle this long; the next call then starts a new run.
        anchor_tsa_url: RFC 3161 authority the chain heads are time-stamped at (SPEC 8); empty
            turns anchoring off. Suggested: https://timestamp.sigstore.dev/api/v1/timestamp.
        anchor_tsa_fallback_url: Second authority tried when the first fails, for example
            http://timestamp.digicert.com.
        anchor_rekor_url: Sigstore Rekor v1 log the heads are also published to (SPEC 8.1.2),
            for example https://rekor.sigstore.dev; empty = off. The log gives transparency,
            the authority gives time: use both.
        anchor_interval_seconds: How often every open run whose head moved is anchored.
        anchor_timeout_seconds: Time allowed for one authority call.

    """

    model_config = SettingsConfigDict(env_prefix="SEALEDRUN_", env_file=".env", extra="ignore")

    data_dir: Path = Path("data")
    database_url: str | None = None
    ui_dir: Path | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    max_bundle_bytes: int = 256 * 1024 * 1024
    api_token: SecretStr | None = None
    allowed_hosts: list[str] = ["127.0.0.1", "localhost"]
    trusted_principals: list[str] = []
    upstreams_file: Path = Path("upstreams.yaml")
    proxy_timeout_seconds: float = 600.0
    proxy_max_body_bytes: int = 32 * 1024 * 1024
    proxy_run_idle_seconds: float = 900.0
    anchor_tsa_url: str = ""
    anchor_tsa_fallback_url: str = ""
    anchor_rekor_url: str = ""
    anchor_interval_seconds: float = 600.0
    anchor_timeout_seconds: float = 20.0

    @property
    def trust_anchor(self) -> frozenset[str] | None:
        """Return the trusted Principal ids, or None when none are configured."""
        return frozenset(self.trusted_principals) or None

    @property
    def resolved_database_url(self) -> str:
        """Return `database_url`, defaulting to a SQLite file inside `data_dir`."""
        return self.database_url or f"sqlite:///{self.data_dir / 'sealedrun.db'}"


def load_settings() -> Settings:
    """Build settings from the environment and the .env file."""
    return Settings()
