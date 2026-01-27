import logging
from typing import List

from app.models.domain import Email
from app.models.risk import RiskAssessment, RiskLevel, DetectorResult
from app.detectors.registry import DetectorRegistry
from app.constants.scoring import RiskThresholds

logger = logging.getLogger(__name__)


class ScoringService:
    """Combines heuristic detector results into a unified risk score."""

    def __init__(self, detectors: List["BaseDetector"] | None = None):
        self.detectors = detectors or DetectorRegistry.get_all_detectors()

    def calculate_risk(self, email: Email) -> RiskAssessment:
        """Calculate overall phishing risk by aggregating detectors scores.
        Args:
            email: Parsed email object to analyze.
        Returns:
            RiskAssessment with final score, level, and detailed reasons.
        """
        score = 0.0
        details = []
        reasons = []

        for detector in self.detectors:
            try:
                result = detector.evaluate(email)
                if result:
                    score += result.score_impact
                    details.append(result)
                    reasons.append(result.description)
            except Exception as e:
                logger.error(f"Detector {detector} failed: {e}")
                continue

        score = min(score, 100.0)
        
        return RiskAssessment(
            score=round(score, 1),
            level=self._determine_risk_level(score),
            reasons=reasons,
            details=details,
        )

    def _determine_risk_level(self, score: float) -> RiskLevel:
        if score >= RiskThresholds.DANGEROUS_LEVEL:
            return RiskLevel.DANGEROUS
        if score >= RiskThresholds.SUSPICIOUS_LEVEL:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.SAFE
