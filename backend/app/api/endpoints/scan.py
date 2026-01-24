from fastapi import APIRouter, Depends

from app.api.dependencies import get_ml_service, get_scoring_service
from app.models.email_request import EmailRequest
from app.models.scan_response import ScanResponse
from app.services.email_parser import EmailParser
from app.services.ml_service import MLService
from app.services.scoring_service import ScoringService


router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_email(
    email_request: EmailRequest,
    ml_service: MLService = Depends(get_ml_service),
    scoring_service: ScoringService = Depends(get_scoring_service),
) -> ScanResponse:
    # 1. Parse the raw MIME content into structured Email object
    email_parser = EmailParser(email_request.mime)
    parsed_email = email_parser.parse()

    # 2. ML model analysis on text content
    subject = parsed_email.subject or ''
    body = parsed_email.body_plain or ''
    text_content = f"{subject} {body}".strip()
    ml_result = ml_service.predict(text_content)

    # 3. Run all detectors and combine with ML score
    risk_assessment = scoring_service.calculate_risk(
        parsed_email,
        ml_score=ml_result.confidence,
        ml_is_phishing=ml_result.is_phishing,
    )

    return ScanResponse.from_results(risk=risk_assessment, ml=ml_result)
