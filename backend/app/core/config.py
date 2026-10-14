from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "ThreatLens AI"
    database_url: str = "sqlite:///./data/threatlens.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"
    max_upload_mb: int = 25
    model_path: str = "ml/artifacts/malware_classifier.pkl"
    feature_schema_path: str = "ml/artifacts/feature_schema.json"
    yara_rules_dir: str = "yara_rules"
    jwt_secret: str = "CHANGE_ME_BEFORE_DEPLOYMENT_TO_A_LONG_RANDOM_SECRET"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 60
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = ""
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    @property
    def origins(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]
settings = Settings()
