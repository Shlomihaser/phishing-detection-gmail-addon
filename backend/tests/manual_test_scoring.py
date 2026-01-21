import sys
import os
from datetime import datetime

# Add base path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.domain import Email, AuthHeaders, Link
from app.services.scoring_service import ScoringService

def test_scoring():
    service = ScoringService()
    
    print("--- Test 1: Safe Email ---")
    safe_email = Email(
        message_id="1",
        sender_name="Google",
        sender_email="no-reply@google.com",
        reply_to="no-reply@google.com",
        subject="Security Alert",
        creation_date=datetime.now(),
        body_text="Your account is safe. No action needed.",
        urls=[Link(url="https://google.com", text="Visit Google")],
        email_addresses=[],
        auth_results=AuthHeaders(spf="pass", dkim="pass", dmarc="pass"),
        headers={}
    )
    result = service.calculate_risk(safe_email)
    print(f"Score: {result.score} | Level: {result.level}")
    print(f"Reasons: {result.reasons}\n")

    print("--- Test 2: Suspicious Email (Urgency + Link) ---")
    sus_email = Email(
        message_id="2",
        sender_name="PayPaI Support", 
        sender_email="support@paypal-secure-verify.com",
        reply_to=None,
        subject="Action Required Immediately",
        creation_date=datetime.now(),
        body_text="Urgent! Your account is suspended. Verify your account immediately.",
        urls=[Link(url="http://192.168.1.1/login", text="Verify Now")], 
        email_addresses=[],
        auth_results=AuthHeaders(spf="softfail", dkim=None, dmarc=None),
        headers={}
    )
    result = service.calculate_risk(sus_email)
    print(f"Score: {result.score} | Level: {result.level}")
    print(f"Reasons: {result.reasons}")
    for detail in result.details:
        print(f" - {detail.rule_name}: {detail.description}")

    print("--- Test 4: Link Mismatch (Hidden URL) ---")
    mismatch_email = Email(
        message_id="3",
        sender_name="CEO",
        sender_email="ceo@company.com",
        reply_to=None,
        subject="Bonus",
        creation_date=datetime.now(),
        body_text="Click here: www.company-portal.com",
        urls=[Link(url="http://evil-phishing-site.com/login", text="www.company-portal.com")], 
        email_addresses=[],
        auth_results=AuthHeaders(spf="pass"),
        headers={}
    )
    result = service.calculate_risk(mismatch_email)
    print(f"Score: {result.score} | Level: {result.level}")
    print(f"Reasons: {result.reasons}")
    for detail in result.details:
        print(f" - {detail.rule_name}: {detail.description}")

if __name__ == "__main__":
    test_scoring()
