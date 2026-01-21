from typing import List
from ..models.internal import Email
from ..models.risk import RiskAssessment, RiskLevel

from .heuristics.base import HeuristicRule
from .heuristics.rules.auth import AuthRule
from .heuristics.rules.sender import SenderMismatchRule
from .heuristics.rules.links import SuspiciousLinkRule
from .heuristics.rules.urgency import UrgencyRule

class ScoringService:
    def __init__(self, rules: List[HeuristicRule] = None):
        """
        Initialize the service with a specific set of rules.
        If no rules are provided, loads the default set.
        """
        if rules is not None:
             self.rules = rules
        else:
            self.rules = [
                AuthRule(),
                SenderMismatchRule(),
                UrgencyRule(),
                SuspiciousLinkRule()
            ]

    def calculate_risk(self, email: Email) -> RiskAssessment:
        total_score = 0.0
        details = []
        reasons = []
        
        for rule in self.rules:
            result = rule.evaluate(email)
            if result:
                total_score += result.score_impact
                details.append(result)
                reasons.append(result.description)

        # Normalize score (0-100)
        total_score = min(max(total_score, 0.0), 100.0)

        # Determine Level
        if total_score >= 70:
            level = RiskLevel.DANGEROUS
        elif total_score >= 30:
            level = RiskLevel.SUSPICIOUS
        else:
            level = RiskLevel.SAFE

        if not reasons:
            reasons.append("No common phishing indicators detected.")

        return RiskAssessment(
            score=total_score,
            level=level,
            reasons=reasons,
            details=details
        )
