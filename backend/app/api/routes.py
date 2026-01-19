from fastapi import APIRouter
from ..models.schemas import EmailRequest, ScanResponse

router = APIRouter()

@router.post("/scan",response_model=ScanResponse)
async def scan_email(email_data: EmailRequest):
    """
    Endpoint logic:
    Receives email data, triggers analysis, and returns phishing classification.
    """
    print(f"Received scan request for: {email_data.subject} from {email_data.sender}")
    return ScanResponse(
        is_phishing=False,
        score=0.0,
        reasons=[],
        confidence=0.0
    )