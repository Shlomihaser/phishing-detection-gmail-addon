from app.detectors.links import MaliciousLinkDetector
from app.models.domain import Email, Link, AuthHeaders


def test_link_detector_raw_ip():
    """
    Scenario: Raw IP Address usage.
    Attack: Phishers use IPs (http://1.2.3.4) to bypass domain reputation checks.
    Expected: Detector flags it with high risk score (40).
    """
    detector = MaliciousLinkDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[Link(url="http://192.168.1.1/login", text="Click me")],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact >= 40.0
    assert "raw IP address" in result.description


def test_link_masking_detection():
    """
    Scenario: Link Masking (Homograph/Deception).
    Attack: The user sees 'google.com' but the link goes to 'evil.com'.
    Expected: Detector flags mismatch between anchor text and href domain.
    """
    detector = MaliciousLinkDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[Link(url="http://evil.com/login", text="Please visit www.google.com")],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact >= 50.0
    assert "link masking detected" in result.description


def test_url_shortener_detection():
    """
    Scenario: URL Shortener usage.
    Attack: Using bit.ly/etc to hide the destination domain.
    Expected: Detector flags suspicious use of shortener.
    """
    detector = MaliciousLinkDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[Link(url="https://bit.ly/hidden", text="Promo")],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)
    assert result is not None
    assert "URL shortener" in result.description


def test_suspicious_tld():
    """
    Scenario: Suspicious TLD (.xyz, .top, etc).
    Attack: Cheap domains often used for burner phishing sites.
    Expected: Detector assigns a lower but non-zero risk score (20).
    """
    detector = MaliciousLinkDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[Link(url="http://cheap-pharmacy.xyz", text="Buy Now")],
        attachments=[],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)
    assert result is not None
    assert "Top-Level Domain" in result.description
