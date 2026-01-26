from fastapi import APIRouter, Depends

from app.api.dependencies import get_ml_service, get_scoring_service
from app.models.email_request import EmailRequest
from app.models.scan_response import ScanResponse
from app.services.email_parser import EmailParser
from app.services.ml_service import MLService
from app.services.scoring_service import ScoringService


router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan_email(
    email_request: EmailRequest,
    ml_service: MLService = Depends(get_ml_service),
    scoring_service: ScoringService = Depends(get_scoring_service),
) -> ScanResponse:
    email_parser = EmailParser(email_request.mime)
    parsed_email = email_parser.parse()

    text_content = f"{parsed_email.subject} {parsed_email.body_plain}".strip()
    ml_result = ml_service.predict(text_content)
    
    risk_assessment = scoring_service.calculate_risk(
        parsed_email,
        ml_result=ml_result,
    )

    return ScanResponse.from_results(risk=risk_assessment, ml=ml_result)

