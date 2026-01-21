from typing import Optional
from ....models.domain import Email
from ....models.risk import HeuristicDetail
from ..base import HeuristicRule

class UrgencyRule(HeuristicRule):
    def evaluate(self, email: Email) -> Optional[HeuristicDetail]:
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
            return HeuristicDetail(
                rule_name="Urgent Language",
                score_impact=impact,
                description=f"Detected urgent or pressuring language: {', '.join(found_triggers[:3])}"
            )
        return None
