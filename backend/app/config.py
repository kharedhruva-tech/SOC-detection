import os
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Integrated SOC Platform"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cyberpunk_soc_secret_key_change_me_in_production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 1 week

    # CORS — allow all origins in dev (override in prod)
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000", 
        "http://127.0.0.1:3000",
        "https://soc-detection.vercel.app",
        # Allow wildcard vercel domains for preview deployments
        "https://*.vercel.app"
    ]

    # Database Settings
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")
    POSTGRES_SERVER: str = os.getenv("POSTGRES_SERVER", "localhost")
    POSTGRES_PORT: str = os.getenv("POSTGRES_PORT", "5432")
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "soc_db")

    # Fallback SQLite DB path (relative to backend dir)
    SQLITE_DB_PATH: str = "soc_platform.db"

    @property
    def DATABASE_URL(self) -> str:
        use_postgres = os.getenv("USE_POSTGRES", "false").lower() == "true"
        if use_postgres:
            return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        else:
            return f"sqlite:///./{self.SQLITE_DB_PATH}"

    class Config:
        case_sensitive = True

settings = Settings()
