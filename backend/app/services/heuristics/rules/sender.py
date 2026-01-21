from typing import Optional
from ....models.domain import Email
from ....models.risk import HeuristicDetail
from ..base import HeuristicRule

class SenderMismatchRule(HeuristicRule):
    def evaluate(self, email: Email) -> Optional[HeuristicDetail]:
        # Check 1: Reply-To different from Sender
        if email.reply_to:
            sender_domain = email.sender_email.split('@')[-1].lower()
            reply_domain = email.reply_to.split('@')[-1].lower()
            
            if sender_domain != reply_domain:
                 return HeuristicDetail(
                    rule_name="Sender/Reply-To Mismatch",
                    score_impact=20.0,
                    description=f"Reply-To address ({email.reply_to}) does not match sender domain ({sender_domain})."
                )
        return None
