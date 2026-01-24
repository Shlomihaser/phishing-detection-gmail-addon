from functools import lru_cache
from app.services.scoring_service import ScoringService
from app.services.ml_service import MLService


@lru_cache(maxsize=1)
def get_ml_service() -> MLService:
    return MLService()


@lru_cache(maxsize=1)
def get_scoring_service() -> ScoringService:
    return ScoringService()
