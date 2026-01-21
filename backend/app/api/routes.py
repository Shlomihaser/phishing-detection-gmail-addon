from fastapi import APIRouter
from ..models.email_request import EmailRequest
from ..models.scan_response import ScanResponse
from ..services.email_parser import EmailParser
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

    # 2. Heuristic based analysis
    scanner = Scanner(parsed_email)
    scan_result = scanner.scan()
    
    # 3. ML model based analysis
    # TODO: Implement in next phase
    
    # ! TODO: Remove this mock response 
    return {
        "status": scan_result.status,
        "confidence": scan_result.confidence,
        
    }