from abc import ABC, abstractmethod
from typing import Optional
from app.models.domain import Email
from app.models.risk import DetectorResult


class BaseDetector(ABC):
    @abstractmethod
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        pass
