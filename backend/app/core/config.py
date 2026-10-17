from pathlib import Path
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "ThreatLens AI"
    environment: str = "development"
    database_url: str = "sqlite:///./data/threatlens.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"
    max_upload_mb: int = Field(default=25, ge=1, le=250)
    model_path: str = "ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/threatlens_pe_random_forest.joblib"
    feature_schema_path: str = "ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/feature_schema.json"
    yara_rules_dir: str = "yara_rules"
    jwt_secret: str = "CHANGE_ME_BEFORE_DEPLOYMENT_TO_A_LONG_RANDOM_SECRET"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = Field(default=30, ge=5, le=1440)
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    @field_validator("environment")
    @classmethod
    def normalize_environment(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"development", "test", "production"}:
            raise ValueError("ENVIRONMENT must be development, test, or production")
        return value

    @property
    def origins(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

    @property
    def hosts(self):
        return [x.strip() for x in self.trusted_hosts.split(",") if x.strip()]
settings = Settings()
