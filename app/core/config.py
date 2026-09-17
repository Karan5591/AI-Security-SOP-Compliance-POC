"""
Central configuration for the Security SOP Compliance POC.
All values are read from environment variables (see .env.example).
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Postgres / pgvector ---
    database_url: str = "postgresql://postgres:postgres@localhost:5432/secsop"

    # --- Embeddings ---
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dim: int = 384  # must match the embedding_model's output size

    # --- LLM (Llama 3 70B, or any OpenAI-chat-compatible gateway) ---
    llm_base_url: str = "http://localhost:8001/v1"
    llm_api_key: str = "changeme"
    llm_model: str = "llama3-70b"
    llm_timeout_seconds: int = 120

    # --- RAG retrieval ---
    top_k_rules: int = 7

    # --- CI security gate ---
    # Critical and High findings fail builds. Unknown severity always blocks.
    blocking_severities: str = "CRITICAL,HIGH"
    security_override_token: str = ""
    max_batch_files: int = 100
    max_file_bytes: int = 512_000

    # --- App ---
    app_name: str = "AI-Security-SOP-Compliance-POC"
    log_level: str = "INFO"

    # --- API auth ---
    # Required on /sop/* and /review via the X-API-Key header. /health stays
    # open (needed for Docker healthchecks, which don't send custom headers).
    api_key: str = "changeme-please-set-a-real-key"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
