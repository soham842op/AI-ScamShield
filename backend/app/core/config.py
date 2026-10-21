from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Anything but "development" is treated as production, so a missing value fails safe.
    app_env: str = "production"
    log_level: str = "info"

    database_url: SecretStr = SecretStr("")
    client_id_hash_key: SecretStr = SecretStr("")
    trusted_proxy_hops: int = 0

    rate_limit_analyze_per_minute: int = 10
    rate_limit_analyze_per_day: int = 100
    rate_limit_feedback_per_hour: int = 30

    url_intel_provider: str = "none"
    url_intel_api_key: SecretStr = SecretStr("")
    url_intel_timeout_ms: int = 2000
    url_intel_daily_budget: int = 5000

    llm_provider: str = "gemini"
    gemini_api_key: SecretStr = SecretStr("")
    llm_model: str = ""
    llm_timeout_ms: int = 6000
    llm_daily_budget: int = 1000
    llm_cooldown_seconds: int = 60

    model_artifact_path: str = "ml/artifacts/current/model.joblib"
    model_artifact_sha256: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
