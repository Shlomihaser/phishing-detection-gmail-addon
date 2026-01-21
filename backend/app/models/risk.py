from pydantic import BaseModel
from typing import List
from enum import Enum

class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"

class HeuristicDetail(BaseModel):
    rule_name: str
    score_impact: float
    description: str

class RiskAssessment(BaseModel):
    score: float 
    level: RiskLevel
    reasons: List[str] 
    details: List[HeuristicDetail] 
