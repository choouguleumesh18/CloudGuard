from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "CloudGuard"
    app_version: str = "2.0.0"
    database_url: str = "sqlite:///./cloudguard.db"
    jwt_secret: str = "CHANGE_ME_USE_A_RANDOM_SECRET_AT_LEAST_32_CHARS"
    jwt_expiry_minutes: int = 60
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = "ChangeMe-Immediately-123!"
    azure_mode: str = "mock"
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None
    azure_client_secret: str | None = None
    azure_default_subscription_id: str | None = None
    auto_remediate_low_risk: bool = False
    execution_mode: str = "inline"
    auto_create_schema: bool = True
    kubernetes_namespace: str = "cloudguard"
    worker_image: str = "cloudguard:local"
    retry_limit: int = 3
    retry_base_seconds: float = 0.25
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
