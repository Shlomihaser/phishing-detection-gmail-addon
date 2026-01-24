import logging
from typing import List, NamedTuple

from app.models.domain import Email
from app.models.risk import RiskAssessment, RiskLevel, DetectorResult
from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry
from app.constants.scoring import RiskThresholds

logger = logging.getLogger(__name__)


class DetectorAnalysis(NamedTuple):
    score: float
    details: list[DetectorResult]
    reasons: list[str]
    is_critical: bool


class ScoringService:
    """Combines heuristic detector results with ML predictions into a unified risk score."""

    def __init__(self, detectors: List[BaseDetector] | None = None):
        self.detectors = detectors or DetectorRegistry.get_all_detectors()

    def calculate_risk(
        self, email: Email, ml_score: float = 0.0, ml_is_phishing: bool = False
    ) -> RiskAssessment:
        """Calculate overall phishing risk by combining detector results with ML score.
        
        Args:
            email: Parsed email object to analyze.
            ml_score: ML model confidence (0.0-1.0).
            ml_is_phishing: Whether ML predicts phishing.
        
        Returns:
            RiskAssessment with final score, level, and detailed reasons.
        """
        analysis = self._run_detectors(email)
        final_score, reasons = self._calculate_final_score(analysis, ml_score, ml_is_phishing)
        level = self._determine_risk_level(final_score)

        return RiskAssessment(
            score=round(final_score, 1),
            level=level,
            reasons=reasons,
            details=analysis.details,
        )

    def _run_detectors(self, email: Email) -> DetectorAnalysis:
        score = 0.0
        details = []
        reasons = []
        is_critical = False

        for detector in self.detectors:
            try:
                result = detector.evaluate(email)
                if result:
                    score += result.score_impact
                    details.append(result)
                    reasons.append(result.description)

                    if result.score_impact >= RiskThresholds.CRITICAL_IMPACT:
                        is_critical = True
            except Exception as e:
                logger.error(f"Detector {detector} failed: {e}")
                continue

        score = min(max(score, 0.0), 100.0)
        return DetectorAnalysis(score=score, details=details, reasons=reasons, is_critical=is_critical)

    def _calculate_final_score(
        self, analysis: DetectorAnalysis, ml_score: float, ml_is_phishing: bool
    ) -> tuple[float, list[str]]:
        reasons = list(analysis.reasons)
        ml_score_100 = ml_score * 100.0

        if analysis.is_critical:
            reasons.insert(0, "CRITICAL: A high-severity indicator was detected. ML score overridden.")
            return 100.0, reasons

        final_score = (analysis.score * RiskThresholds.DETECTOR_WEIGHT) + (
            ml_score_100 * RiskThresholds.ML_WEIGHT
        )

        if self._should_boost_ml_score(ml_is_phishing, ml_score, analysis.score):
            reasons.append(f"AI Model detected suspicious patterns (Confidence: {int(ml_score_100)}%).")
            final_score = max(final_score, RiskThresholds.ML_BOOST_MINIMUM)

        return min(final_score, 100.0), reasons

    def _should_boost_ml_score(
        self, ml_is_phishing: bool, ml_score: float, detector_score: float
    ) -> bool:
        return (
            ml_is_phishing
            and ml_score > RiskThresholds.ML_HIGH_CONFIDENCE
            and detector_score < RiskThresholds.SUSPICIOUS_LEVEL
        )

    def _determine_risk_level(self, score: float) -> RiskLevel:
        if score >= RiskThresholds.DANGEROUS_LEVEL:
            return RiskLevel.DANGEROUS
        if score >= RiskThresholds.SUSPICIOUS_LEVEL:
            return RiskLevel.SUSPICIOUS
        return RiskLevel.SAFE
