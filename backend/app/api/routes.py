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
    # phishing detection logic - heuristic based
    
    # ml model based
    
    # ! TODO: Remove this mock response 
    return {
        "status": "SUSPICIOUS",
        "confidence": 45,
        "classification_icon": "⚠️",
        "key_signals": [
            "Urgent language detected",
            "Sender from free email provider",
            "Contains suspicious short-links"
        ],
        "message": "This email shows signs of a phishing attempt. Exercise caution."
    }