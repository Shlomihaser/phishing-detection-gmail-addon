from pydantic import BaseModel
from typing import List


class DetectorDetail(BaseModel):
    name: str
    impact: float
    description: str


class ScanDetails(BaseModel):
    ml_score: float
    ml_prediction: str
    detectors: List[DetectorDetail]


class ScanResponse(BaseModel):
    status: str
    confidence: float
    reasons: List[str]
    details: ScanDetails
