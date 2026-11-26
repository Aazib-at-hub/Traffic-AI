"""Application configuration powered by pydantic-settings."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    app_name: str = "NetSentinel AI"
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"

    # Database
    database_url: str = "sqlite:///./netsentinel_dev.db"

    # Redis & Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"
    celery_task_always_eager: bool = True

    # Storage (s3 | local)
    storage_backend: str = "local"
    s3_endpoint_url: str = "http://localhost:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket_name: str = "netsentinel-data"
    s3_region: str = "us-east-1"
    local_storage_dir: str = "./data/storage"

    # Auth & Security
    jwt_secret_key: str = "dev-insecure-secret-change-in-production-32bytes"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    jwt_refresh_token_expire_days: int = 7
    max_pcap_size_mb: int = 500

    # LLM Provider Abstraction (gemini | openai_compatible | mock)
    llm_provider: str = "mock"
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model_name: str = "gemini-2.0-flash"
    llm_timeout_seconds: int = 25

    # RAG
    embedding_model: str = "BAAI/bge-base-en-v1.5"
    embedding_dim: int = 768
    reranker_model: str = "BAAI/bge-reranker-base"
    use_local_hash_embedder: bool = True

    # Observability
    otel_exporter_otlp_endpoint: str = ""
    langfuse_host: str = ""
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
