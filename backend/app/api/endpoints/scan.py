from fastapi import APIRouter
from app.models.email_request import EmailRequest
from app.services.email_parser import EmailParser
from app.services.scoring_service import ScoringService
from app.services.ml_service import MLService
from app.models.risk import RiskLevel
from app.models.scan_response import ScanResponse

router = APIRouter()
scoring_service = ScoringService()
ml_service = MLService()

@router.post("/scan", response_model=ScanResponse)
async def scan_email(email_data: EmailRequest):
    """
    Endpoint logic:
    Receives email data, triggers analysis (Detectors + ML), and returns phishing classification.
    """
    print(f"Received scan request for: {email_data.subject} from {email_data.sender}")

    # 1. Email parsing
    parser = EmailParser(email_data)
    parsed_email = parser.parse()

    # 2. Detectors based analysis
    risk_assessment = scoring_service.calculate_risk(parsed_email)
    
    # 3. ML model based analysis
    # Combined Subject + Body for the model
    text_content = f"{email_data.subject} {email_data.body}"
    ml_result = ml_service.predict(text_content)
    
    # 4. Integrate ML Score into Confidence
    # Strategy: 
    # - Detectors Score is 0-100.
    # - ML Confidence is 0.0-1.0 (for Phishing).
    # - We want a unified view.
    
    detectors_score = risk_assessment.score # 0-100
    ml_score = ml_result['confidence'] * 100 # Scale to 0-100
    
    # If ML strongly predicts phishing, it overrides valid-looking detectors (unless whitelisted).
    # If Detectors see specific danger (like typoquatting) that ML missed, we keep it high.
    
    final_score = max(detectors_score, ml_score)
    
    # Determine Status based on final score
    if final_score >= 70:
        status = RiskLevel.DANGEROUS
    elif final_score >= 30:
        status = RiskLevel.SUSPICIOUS
    else:
        status = RiskLevel.SAFE

    # Add ML details to reasons if relevant
    if ml_result['is_phishing']:
        risk_assessment.reasons.append(f"ML Model detected patterns consistent with phishing (Confidence: {ml_result['confidence']:.2f})")

    return {
        "status": status,
        "confidence": final_score, # 0-100
        "reasons": risk_assessment.reasons,
        "details": {
            "detectors_score": detectors_score,
            "ml_score": ml_score
        }
    }