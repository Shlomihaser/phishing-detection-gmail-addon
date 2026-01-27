from functools import lru_cache
from app.services.scoring_service import ScoringService


@lru_cache(maxsize=1)
def get_scoring_service() -> ScoringService:
    return ScoringService()
