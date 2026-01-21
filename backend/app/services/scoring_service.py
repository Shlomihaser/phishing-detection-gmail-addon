from typing import List
from ..models.domain import Email
from ..models.risk import RiskAssessment, RiskLevel

from app.detectors.base import BaseDetector
from app.detectors.auth import AuthDetector
from app.detectors.sender import SenderMismatchDetector
from app.detectors.links import SuspiciousLinkDetector
from app.detectors.urgency import UrgencyDetector
from app.detectors.mismatch import LinkMismatchDetector

class ScoringService:
    def __init__(self, detectors: List[BaseDetector] = None):
        """
        Initialize the service with a specific set of detectors.
        If no detectors are provided, loads the default set.
        """
        if detectors is not None:
             self.detectors = detectors
        else:
            self.detectors = [
                AuthDetector(),
                SenderMismatchDetector(),
                UrgencyDetector(),
                SuspiciousLinkDetector(),
                LinkMismatchDetector()
            ]

    def calculate_risk(self, email: Email) -> RiskAssessment:
        total_score = 0.0
        details = []
        reasons = []
        
        for detector in self.detectors:
            result = detector.evaluate(email)
            if result:
                total_score += result.score_impact
                details.append(result)
                reasons.append(result.description)

        # Normalize score (0-100)
        total_score = min(max(total_score, 0.0), 100.0)

        # Determine Level
        if total_score >= 70:
            level = RiskLevel.DANGEROUS
        elif total_score >= 30:
            level = RiskLevel.SUSPICIOUS
        else:
            level = RiskLevel.SAFE

        if not reasons:
            reasons.append("No common phishing indicators detected.")

        return RiskAssessment(
            score=total_score,
            level=level,
            reasons=reasons,
            details=details
        )
