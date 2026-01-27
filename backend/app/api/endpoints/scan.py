from fastapi import APIRouter, Depends

from app.api.dependencies import get_scoring_service
from app.models.email_request import EmailRequest
from app.models.scan_response import ScanResponse
from app.services.email_parser import EmailParser
from app.services.scoring_service import ScoringService


router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan_email(
    email_request: EmailRequest,
    scoring_service: ScoringService = Depends(get_scoring_service),
) -> ScanResponse:

    email_parser = EmailParser(email_request.mime)
    parsed_email = email_parser.parse()
    
    risk_assessment = scoring_service.calculate_risk(parsed_email)

    return ScanResponse.from_results(risk=risk_assessment)

