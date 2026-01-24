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

    text_content = _build_text_content(parsed_email)
    ml_result = ml_service.predict(text_content)

    risk_assessment = scoring_service.calculate_risk(
        parsed_email,
        ml_score=ml_result.confidence,
        ml_is_phishing=ml_result.is_phishing,
    )

    return ScanResponse.from_results(risk=risk_assessment, ml=ml_result)


def _build_text_content(email) -> str:
    subject = email.subject or ""
    body = email.body_plain or ""
    return f"{subject} {body}".strip()
