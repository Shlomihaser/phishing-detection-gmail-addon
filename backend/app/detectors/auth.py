from typing import Optional
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.base import BaseDetector

class AuthDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        auth = email.auth_results
        failed = []
        
        if auth.spf and auth.spf.lower() in ["fail", "softfail"]:
            failed.append("SPF")
        if auth.dkim and auth.dkim.lower() in ["fail"]:
            failed.append("DKIM")
        if auth.dmarc and auth.dmarc.lower() in ["fail"]:
            failed.append("DMARC")
            
        if failed:
            return DetectorResult(
                detector_name="Authentication Failure",
                score_impact=30.0 * len(failed),
                description=f"Email failed authentication checks: {', '.join(failed)}"
            )
        return None
