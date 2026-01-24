from app.models.risk import RiskLevel
from pydantic import BaseModel
from typing import List

from app.models.risk import DetectorResult, MLPrediction, RiskAssessment


class DetectorDetail(BaseModel):
    name: str
    impact: float
    description: str

    @classmethod
    def from_risk_result(cls, result: DetectorResult) -> "DetectorDetail":
        return cls(
            name=result.detector_name,
            impact=result.score_impact,
            description=result.description,
        )


class ScanDetails(BaseModel):
    ml_score: float
    ml_prediction: str
    detectors: List[DetectorDetail]

    @classmethod
    def create(
        cls, ml: MLPrediction, detector_results: List[DetectorResult]
    ) -> "ScanDetails":
        return cls(
            ml_score=round(ml.confidence * 100, 1),
            ml_prediction=RiskLevel.DANGEROUS if ml.is_phishing else RiskLevel.SAFE,
            detectors=[DetectorDetail.from_risk_result(d) for d in detector_results],
        )


class ScanResponse(BaseModel):
    status: str
    confidence: float
    reasons: List[str]
    details: ScanDetails

    @classmethod
    def from_results(
        cls, risk: RiskAssessment, ml: MLPrediction
    ) -> "ScanResponse":
        return cls(
            status=risk.level.value,
            confidence=risk.score,
            reasons=risk.reasons,
            details=ScanDetails.create(ml, risk.details),
        )
