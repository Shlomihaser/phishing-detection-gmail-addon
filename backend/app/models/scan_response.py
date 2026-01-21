from pydantic import BaseModel, Field
from typing import List

class ScanResponse(BaseModel):
    """Schema for the phishing analysis results returned to the user."""
    status: str = Field(..., description="Risk label: Safe, Suspicious, or Phishing")
    confidence: float = Field(..., ge=0, le=100, description="Confidence score from 0 to 100")
    key_signals: List[str] = Field(default_factory=list, description="List of triggered phishing signals")
