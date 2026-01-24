from app.detectors.brand_protection import BrandProtectionDetector
from app.models.domain import Email, AuthHeaders


def test_brand_impersonation_name():
    """
    Scenario: Sender Name Impersonation.
    Attack: Sender Name is 'Microsoft Security' but email is 'hacker@gmail.com'.
    Expected: Detector flags that the name claims high value brand, but domain is unrelated.
    """
    detector = BrandProtectionDetector()
    email = Email(
        sender_email="random@gmail.com",
        sender_name="Microsoft Support Team",
        reply_to=None,
        urls=[],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact >= 75.0
    assert "claims to be 'Microsoft'" in result.description


def test_brand_typosquatting_domain():
    """
    Scenario: Domain Typosquatting (Homoglyphs/Distance).
    Attack: Sender is 'admin@micosoft.com' (missing 'r').
    Expected: Detector sees standard Levenshtein distance match to 'microsoft'.
    """
    detector = BrandProtectionDetector()
    email = Email(
        sender_email="admin@micosoft.com",  # Typo: micosoft vs microsoft
        sender_name="Admin",
        reply_to=None,
        urls=[],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert "mimics protected brand 'microsoft'" in result.description.lower()


def test_brand_legitimate_pass():
    """
    Scenario: Legitimate Email from Brand.
    Case: Sender is 'bill@microsoft.com'.
    Expected: Detector recognizes 'microsoft.com' is in VALID_DOMAINS for 'Microsoft', so NO ALERT.
    """
    detector = BrandProtectionDetector()
    email = Email(
        sender_email="bill@microsoft.com",
        sender_name="Microsoft Billing",
        reply_to=None,
        urls=[],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)
    assert result is None  # Should pass safely
