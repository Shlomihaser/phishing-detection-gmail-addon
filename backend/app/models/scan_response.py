from pydantic import BaseModel
from typing import List

from app.models.risk import DetectorResult, RiskAssessment


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
    detectors: List[DetectorDetail]

    @classmethod
    def create(
        cls, detector_results: List[DetectorResult]
    ) -> "ScanDetails":
        return cls(
            detectors=[DetectorDetail.from_risk_result(d) for d in detector_results],
        )


class ScanResponse(BaseModel):
    status: str
    confidence: float
    reasons: List[str]
    details: ScanDetails

    @classmethod
    def from_results(cls, risk: RiskAssessment) -> "ScanResponse":
        return cls(
            status=risk.level.value,
            confidence=risk.score,
            reasons=risk.reasons,
            details=ScanDetails.create(risk.details),
        )
