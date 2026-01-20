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
        classification="Safe",        
        confidence_score=0.1,      
        reasons=["Initial connectivity test successful"]
    )