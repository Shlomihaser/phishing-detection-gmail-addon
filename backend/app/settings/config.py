import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PORT: int = 8000
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    
    @property
    def ML_DIR(self) -> Path:
        return self.BASE_DIR / "ml"

    @property
    def PHISHING_MODEL_PATH(self) -> Path:
        return self.ML_DIR / "phishing_model_bert.joblib"

    @property
    def DATASET_PATH(self) -> Path:
        return self.ML_DIR / "Phishing_Email.csv"


    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
