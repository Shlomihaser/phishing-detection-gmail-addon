from fastapi import APIRouter
from ..models.email_request import EmailRequest
from ..services.email_parser import EmailParser
from ..services.scoring_service import ScoringService
from ..services.ml_service import MLService
from ..models.risk import RiskLevel
from ..models.scan_response import ScanResponse

router = APIRouter()
scoring_service = ScoringService()
ml_service = MLService()

@router.post("/scan", response_model=ScanResponse)
async def scan_email(email_data: EmailRequest):
    """
    Endpoint logic:
    Receives email data, triggers analysis (Heuristics + ML), and returns phishing classification.
    """
    print(f"Received scan request for: {email_data.subject} from {email_data.sender}")

    # 1. Email parsing
    parser = EmailParser(email_data)
    parsed_email = parser.parse()

    # 2. Heuristic based analysis
    risk_assessment = scoring_service.calculate_risk(parsed_email)
    
    # 3. ML model based analysis
    # Combined Subject + Body for the model
    text_content = f"{email_data.subject} {email_data.body}"
    ml_result = ml_service.predict(text_content)
    
    # 4. Integrate ML Score into Confidence
    # Strategy: 
    # - Heuristic Score is 0-100.
    # - ML Confidence is 0.0-1.0 (for Phishing).
    # - We want a unified view.
    
    heuristic_score = risk_assessment.score # 0-100
    ml_score = ml_result['confidence'] * 100 # Scale to 0-100
    
    # If ML strongly predicts phishing, it overrides valid-looking heuristics (unless whitelisted).
    # If Heuristics see specific danger (like typoquatting) that ML missed, we keep it high.
    
    final_score = max(heuristic_score, ml_score)
    
    # Determine Status based on final score
    if final_score >= 70:
        status = "dangerous"
    elif final_score >= 30:
        status = "suspicious"
    else:
        status = "safe"

    # Add ML details to reasons if relevant
    if ml_result['is_phishing']:
        risk_assessment.reasons.append(f"ML Model detected patterns consistent with phishing (Confidence: {ml_result['confidence']:.2f})")

    return {
        "status": status,
        "confidence": final_score, # 0-100
        "reasons": risk_assessment.reasons,
        "details": {
            "heuristic_score": heuristic_score,
            "ml_score": ml_score
        }
    }