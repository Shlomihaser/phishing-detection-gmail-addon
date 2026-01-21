from fastapi import APIRouter
from ..models.email_request import EmailRequest
from ..models.scan_response import ScanResponse
from ..services.email_parser import EmailParser
import json
router = APIRouter()

@router.post("/scan",response_model=dict)
async def scan_email(email_data: EmailRequest):
    """
    Endpoint logic:
    Receives email data, triggers analysis, and returns phishing classification.
    """
    print(f"Received scan request for: {email_data.subject} from {email_data.sender}")

    # 1. Email parsing
    parser = EmailParser(email_data)
    parsed_email = parser.parse()
    clean_json = json.dumps(parsed_email.model_dump(), indent=4, default=str)
    
    print("\n" + "="*50)
    print("🚀 NEW EMAIL PARSED SUCCESSFULLY")
    print("="*50)
    print(clean_json)
    print("="*50 + "\n")

    # 2. Heuristic based analysis
    # TODO: Implement in next phase
    
    # 3. ML model based analysis
    # TODO: Implement in next phase
    
    # ! TODO: Remove this mock response 
    return {
        "status": "SUSPICIOUS",
        "confidence": 45,        
        "key_signals": [                    
            "Urgent language detected",
            "Sender from free email provider",
            "Contains suspicious short-links",
            f"Parsed Subject: {parsed_email.subject}",
            f"SPF Status: {parsed_email.auth_results.spf}"
        ]
    }