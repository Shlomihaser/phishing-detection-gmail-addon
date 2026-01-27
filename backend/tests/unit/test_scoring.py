from unittest.mock import MagicMock
from app.services.scoring_service import ScoringService, RiskLevel
from app.models.risk import DetectorResult




def test_scoring_accumulation():
    """
    Scenario: Accumulation of scores.
    Condition: Detector A (30), Detector B (40).
    Goal: Verify score is 70.
    """
    d1 = MagicMock()
    d1.evaluate.return_value = DetectorResult(
        detector_name="D1", score_impact=30.0, description="D1 found something"
    )
    d2 = MagicMock()
    d2.evaluate.return_value = DetectorResult(
        detector_name="D2", score_impact=40.0, description="D2 found something"
    )

    service = ScoringService(detectors=[d1, d2])

    risk = service.calculate_risk(MagicMock())

    assert risk.score == 70.0
    assert risk.level == RiskLevel.DANGEROUS  # Assuming 70 is Dangerous threshold
    assert len(risk.details) == 2


def test_scoring_cap_at_100():
    """
    Scenario: Score Capping.
    Condition: Detectors sum > 100.
    Goal: Verify score is 100.
    """
    d1 = MagicMock()
    d1.evaluate.return_value = DetectorResult(
        detector_name="D1", score_impact=60.0, description="High"
    )
    d2 = MagicMock()
    d2.evaluate.return_value = DetectorResult(
        detector_name="D2", score_impact=60.0, description="High"
    )

    service = ScoringService(detectors=[d1, d2])
    risk = service.calculate_risk(MagicMock())

    assert risk.score == 100.0
