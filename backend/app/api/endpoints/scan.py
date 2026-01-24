from fastapi import APIRouter, Depends
from app.models.email_request import EmailRequest
from app.models.scan_response import ScanResponse, ScanDetails, DetectorDetail
from app.services.email_parser import EmailParser
from app.services.scoring_service import ScoringService
from app.services.ml_service import MLService
from app.api.dependencies import get_ml_service, get_scoring_service

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_email(
    email_request: EmailRequest,
    ml_service: MLService = Depends(get_ml_service),
    scoring_service: ScoringService = Depends(get_scoring_service)
) -> ScanResponse:

    # 1. Parse the raw MIME content into structured Email object
    parser = EmailParser(email_request.mime)
    parsed_email = parser.parse()
    
    # 2. ML model analysis on text content
    text_content = f"{parsed_email.subject or ''} {parsed_email.body_plain or ''}"
    ml_result = ml_service.predict(text_content)
    
    # 3. Run all detectors and combine with ML score
    risk_assessment = scoring_service.calculate_risk(
        parsed_email, 
        ml_score=ml_result['confidence'], 
        ml_is_phishing=ml_result['is_phishing']
    )

    return ScanResponse(
        status=risk_assessment.level.value,
        confidence=risk_assessment.score,
        reasons=risk_assessment.reasons,
        details=ScanDetails(
            ml_score=round(ml_result['confidence'] * 100, 1),
            ml_prediction="phishing" if ml_result['is_phishing'] else "safe",
            detectors=[
                DetectorDetail(
                    name=d.detector_name,
                    impact=d.score_impact,
                    description=d.description
                )
                for d in risk_assessment.details
            ]
        )
    )

