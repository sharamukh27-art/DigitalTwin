"""Application settings, read from environment variables and the .env file."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Runtime configuration for the whole backend."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Cyber Digital Twin"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"

    mongo_uri: str = "mongodb://localhost:27017"
    mongo_db: str = "cyber_twin"
    mongo_timeout_ms: int = 3000

    log_level: str = "INFO"

    llm_provider: str = "mock"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_default_model: str = "claude-opus-5-5"
    llm_timeout_seconds: float = 120.0
    llm_max_retries: int = 2
    llm_backoff_seconds: float = 1.0
    llm_max_tokens: int = 16000

    chroma_path: str = "./chroma_data"
    kb_collection: str = "cyber_kb"
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    chunk_tokens: int = 220
    chunk_overlap_tokens: int = 40

    cors_origins: list[str] = ["http://localhost:5173"]
    data_dir: Path = BACKEND_ROOT / "data"
    max_import_bytes: int = 5 * 1024 * 1024

    @property
    def techniques_file(self) -> Path:
        """Path of the ATT&CK technique catalog."""
        return self.data_dir / "attack" / "techniques.yaml"

    @property
    def capabilities_file(self) -> Path:
        """Path of the control capability catalog."""
        return self.data_dir / "controls" / "capabilities.yaml"

    @property
    def kb_dir(self) -> Path:
        """Folder holding the knowledge base sources."""
        return self.data_dir / "knowledge_base"

    @property
    def kb_raw_dir(self) -> Path:
        """Folder the knowledge base downloads are written to."""
        return self.kb_dir / "raw"

    @property
    def kb_policies_dir(self) -> Path:
        """Folder holding organisation policy markdown files."""
        return self.kb_dir / "org_policies"

    @property
    def llm_model_name(self) -> str:
        """Model to use: LLM_MODEL when set, otherwise the default."""
        return self.llm_model or self.llm_default_model

    @property
    def scenarios_dir(self) -> Path:
        """Folder holding the scenario YAML files."""
        return self.data_dir / "scenarios"

    @property
    def reference_network_file(self) -> Path:
        """Sample network whose asset codes the scenario library is validated against."""
        return self.data_dir / "sample_networks" / "acme_corp.json"


@lru_cache
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()
