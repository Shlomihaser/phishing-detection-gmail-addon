from pydantic import BaseModel, Field
from typing import Optional, List

class EmailRequest(BaseModel):
    """Schema representing the email data sent from the Gmail Add-on for analysis."""
    subject: str = Field(..., description="The subject line of the email")
    body: str = Field(..., description="The plain text or HTML content of the email body")
    sender: str = Field(..., description="The email address of the sender")
    headers: Optional[str] = Field(None, description="Raw RFC822 headers for advanced analysis")

class ScanResponse(BaseModel):
    """Schema for the phishing analysis results returned to the user."""
    classification: str = Field(..., description="Risk label: Safe, Suspicious, or Phishing")
    confidence_score: float = Field(..., ge=0, le=100, description="Confidence score from 0 to 100")
    reasons: List[str] = Field(default_factory=list, description="List of triggered phishing signals")