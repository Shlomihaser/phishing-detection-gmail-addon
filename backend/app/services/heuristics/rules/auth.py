from typing import Optional
from ....models.domain import Email
from ....models.risk import HeuristicDetail
from ..base import HeuristicRule

class AuthRule(HeuristicRule):
    def evaluate(self, email: Email) -> Optional[HeuristicDetail]:
        auth = email.auth_results
        failed = []
        
        if auth.spf and auth.spf.lower() in ["fail", "softfail"]:
            failed.append("SPF")
        if auth.dkim and auth.dkim.lower() in ["fail"]:
            failed.append("DKIM")
        if auth.dmarc and auth.dmarc.lower() in ["fail"]:
            failed.append("DMARC")
            
        if failed:
            return HeuristicDetail(
                rule_name="Authentication Failure",
                score_impact=30.0 * len(failed),
                description=f"Email failed authentication checks: {', '.join(failed)}"
            )
        return None
