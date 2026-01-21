from pydantic import BaseModel
from typing import List, Dict, Optional

class ScanDetails(BaseModel):
    heuristic_score: float
    ml_score: float

class ScanResponse(BaseModel):
    status: str
    confidence: float
    reasons: List[str]
    details: ScanDetails
