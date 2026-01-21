from abc import ABC, abstractmethod
from typing import Optional
from app.models.domain import Email
from app.models.risk import DetectorResult

class BaseDetector(ABC):
    """
    Abstract Base Class for all phishing detection modules.
    """
    @abstractmethod
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        """
        Evaluates the email against the detection logic.
        Returns a DetectorResult if the detector triggers, or None if it passes validation.
        """
        pass
