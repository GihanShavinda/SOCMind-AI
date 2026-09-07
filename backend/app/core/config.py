from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database / cache
    DATABASE_URL: str = "postgresql+psycopg://socmind:socmind@localhost:5432/socmind"
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Startup
    SEED_ON_STARTUP: bool = False

    # Detection tuning (SSH brute-force slice)
    BRUTEFORCE_FAILED_THRESHOLD: int = 5      # failures within the window -> alert
    BRUTEFORCE_WINDOW_SECONDS: int = 120      # correlation time window

    # Default seed admin (change in real deployments)
    SEED_ADMIN_EMAIL: str = "admin@socmind.io"
    SEED_ADMIN_PASSWORD: str = "ChangeMe123!"


settings = Settings()
