from pydantic import BaseModel
from typing import List
from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"


class DetectorResult(BaseModel):
    detector_name: str
    score_impact: float
    description: str


class RiskAssessment(BaseModel):
    score: float
    level: RiskLevel
    reasons: List[str]
    details: List[DetectorResult]


class MLPrediction(BaseModel):
    is_phishing: bool = False
    confidence: float = 0.0
    is_scanned: bool = True
