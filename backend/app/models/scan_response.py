from pydantic import BaseModel
from typing import List

class ScanDetails(BaseModel):
    detectors_score: float
    ml_score: float

class ScanResponse(BaseModel):
    status: str
    confidence: float
    reasons: List[str]
    details: ScanDetails
