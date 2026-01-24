from unittest.mock import MagicMock
from app.services.scoring_service import ScoringService, RiskLevel, RiskThresholds
from app.models.risk import DetectorResult


def test_scoring_critical_override():
    """
    Scenario: Critical Detector Override.
    Condition: Detectors find a CRITICAL threat (Score > 80, e.g. Executable).
               BUT ML says it's perfectly safe (0.0).
    Goal: Verify that the final score is forced to 100. The heuristic MUST override the ML.
    """
    # Mock a detector that screams "DANGER"
    mock_detector = MagicMock()
    mock_detector.evaluate.return_value = DetectorResult(
        detector_name="Critical", score_impact=100.0, description="Virus Found"
    )

    service = ScoringService(detectors=[mock_detector])

    # ML says "Safe" (0.0)
    risk = service.calculate_risk(MagicMock(), ml_score=0.0, ml_is_phishing=False)

    assert risk.score == 100.0
    assert risk.level == RiskLevel.DANGEROUS
    assert "CRITICAL" in risk.reasons[0]


def test_scoring_weighted_average():
    """
    Scenario: Standard Weighted Scoring.
    Condition: Detectors find suspicious link (50). ML is unsure/neutral (0.5).
    Goal: Verify math: (50 * 0.6) + (50 * 0.4) = 30 + 20 = 50.
    """
    mock_detector = MagicMock()
    mock_detector.evaluate.return_value = DetectorResult(
        detector_name="Link", score_impact=50.0, description="Bad link"
    )

    service = ScoringService(detectors=[mock_detector])

    # ML Score 0.5 (50%)
    risk = service.calculate_risk(MagicMock(), ml_score=0.5, ml_is_phishing=True)

    # Expected: 50.0 total
    assert risk.score == 50.0
    assert risk.level == RiskLevel.SUSPICIOUS


def test_scoring_ml_boost():
    """
    Scenario: ML Boost (AI saves the day).
    Condition: Detectors find NOTHING (0). But ML is VERY confident (0.99).
    Goal: Verify that the score is boosted to at least SUSPICIOUS (50.0),
          instead of being just 40.0 (0*0.6 + 100*0.4).
    """
    # No heuristic triggers
    service = ScoringService(detectors=[])

    # ML is 99% sure it's phishing
    risk = service.calculate_risk(MagicMock(), ml_score=0.99, ml_is_phishing=True)

    # Without boost, it would be 39.6. With boost, it should be >= 50.0
    assert risk.score >= RiskThresholds.ML_BOOST_MINIMUM
    assert "AI Model detected" in risk.reasons[0]
