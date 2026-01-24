from typing import List
from ..models.domain import Email
from ..models.risk import RiskAssessment, RiskLevel

from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry

# Import detectors package to trigger registration
# This single import causes all detector modules to load and register
import app.detectors  # noqa: F401 - import triggers registration


# Risk Scoring Thresholds
class RiskThresholds:
    """Named constants for risk scoring - avoid magic numbers."""
    CRITICAL_IMPACT = 80.0      # Score that triggers critical override
    DANGEROUS_LEVEL = 70.0      # >= this score = DANGEROUS
    SUSPICIOUS_LEVEL = 30.0     # >= this score = SUSPICIOUS, < DANGEROUS
    
    # Weighting
    DETECTOR_WEIGHT = 0.6       # 60% weight for heuristic detectors
    ML_WEIGHT = 0.4             # 40% weight for ML model
    
    # ML Override thresholds
    ML_HIGH_CONFIDENCE = 0.85   # 85% ML confidence triggers boost
    ML_BOOST_MINIMUM = 50.0     # Minimum score when ML is confident


class ScoringService:
    def __init__(self, detectors: List[BaseDetector] = None):
        """
        Initialize the service with a specific set of detectors.
        
        Args:
            detectors: Optional list of detectors. If None, uses all
                      registered detectors from DetectorRegistry.
                      Pass a custom list for testing purposes.
        """
        if detectors is not None:
            self.detectors = detectors
        else:
            self.detectors = DetectorRegistry.get_all_detectors()

    def calculate_risk(self, email: Email, ml_score: float = 0.0, ml_is_phishing: bool = False) -> RiskAssessment:
        detectors_score = 0.0
        details = []
        reasons = []
        
        # 1. Run Heuristics
        critical_trigger = False
        
        for detector in self.detectors:
            result = detector.evaluate(email)
            if result:
                detectors_score += result.score_impact
                details.append(result)
                reasons.append(result.description)
                
                # Critical Trigger Check:
                # If any single detector says "This is critical", we assume it's critical.
                if result.score_impact >= RiskThresholds.CRITICAL_IMPACT:
                    critical_trigger = True

        # Cap detectors score at 100 before weighting
        detectors_score = min(max(detectors_score, 0.0), 100.0)

        # 2. Integrate ML Score
        # ML returns a confidence float 0.0 - 1.0. We map it to 0-100.
        ml_score_100 = ml_score * 100.0
        
        # 3. Calculate Final Weighted Score
        if critical_trigger:
            final_score = 100.0
            reasons.insert(0, "CRITICAL: A high-severity indicator was detected. ML score overridden.")
        else:
            final_score = (detectors_score * RiskThresholds.DETECTOR_WEIGHT) + (ml_score_100 * RiskThresholds.ML_WEIGHT)
            
            # Additional Logic: If Heuristics found NOTHING, but ML is VERY sure, 
            # we should trust ML more than just 40%.
            if ml_is_phishing and ml_score > RiskThresholds.ML_HIGH_CONFIDENCE and detectors_score < RiskThresholds.SUSPICIOUS_LEVEL:
                reasons.append(f"AI Model detected suspicious patterns (Confidence: {int(ml_score_100)}%).")
                # Boost score to at least SUSPICIOUS level if ML is screaming yes
                final_score = max(final_score, RiskThresholds.ML_BOOST_MINIMUM)

        # Cap Final Score
        final_score = min(final_score, 100.0)

        # 4. Determine Level
        if final_score >= RiskThresholds.DANGEROUS_LEVEL:
            level = RiskLevel.DANGEROUS
        elif final_score >= RiskThresholds.SUSPICIOUS_LEVEL:
            level = RiskLevel.SUSPICIOUS
        else:
            level = RiskLevel.SAFE

        return RiskAssessment(
            score=round(final_score, 1),
            level=level,
            reasons=reasons,
            details=details
        )

