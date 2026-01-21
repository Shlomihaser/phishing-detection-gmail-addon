from typing import Optional
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.base import BaseDetector

class UrgencyDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        triggers = [
            "urgent", "action required", "verify your account", 
            "suspended", "locked", "immediately", "24 hours"
        ]
        
        found_triggers = []
        body_lower = email.body_text.lower()
        
        for word in triggers:
            if word in body_lower:
                found_triggers.append(word)
        
        if found_triggers:
            impact = min(10.0 * len(found_triggers), 40.0) 
            return DetectorResult(
                detector_name="Urgent Language",
                score_impact=impact,
                description=f"Detected urgent or pressuring language: {', '.join(found_triggers[:3])}"
            )
        return None
