from app.detectors.header_analysis import HeaderAnalysisDetector
from app.services.email_parser import EmailParser


def test_headers_safe(email_builder):
    """Scenario: Valid headers, proper auth, no mismatches."""
    # Build email
    mime = (
        email_builder.with_sender("alice@example.com")
        .with_header(
            "Authentication-Results",
            "mx.google.com; spf=pass; dkim=pass; dmarc=pass"
        )
        .build()
    )

    email = EmailParser(mime).parse()
    detector = HeaderAnalysisDetector()
    result = detector.evaluate(email)

    assert result is None


def test_headers_spf_fail(email_builder):
    """Scenario: SPF fails explicitly."""
    mime = (
        email_builder.with_sender("alice@example.com")
        .with_header(
            "Authentication-Results",
            "mx.google.com; spf=fail (IP not authorized)"
        )
        .build()
    )

    email = EmailParser(mime).parse()
    detector = HeaderAnalysisDetector()
    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact == 100.0
    assert "SPF authentication failed" in result.description


def test_headers_dmarc_fail(email_builder):
    """Scenario: DMARC fail is extremely critical."""
    mime = (
        email_builder.with_sender("alice@example.com")
        .with_header(
            "Authentication-Results",
            "mx.google.com; dmarc=fail header.from=example.com"
        )
        .build()
    )

    email = EmailParser(mime).parse()
    detector = HeaderAnalysisDetector()
    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact == 100.0
    assert "DMARC policy failed" in result.description


def test_reply_to_mismatch(email_builder):
    """Scenario: Sender differs from Reply-To."""
    mime = (
        email_builder.with_sender("ceo@company.com")
        .with_header("Reply-To", "hacker@evil.com")
        .build()
    )

    email = EmailParser(mime).parse()
    detector = HeaderAnalysisDetector()
    result = detector.evaluate(email)

    assert result is not None
    assert "Reply-To domain mismatch" in result.description
    assert result.score_impact >= 60.0


def test_reply_to_whitelist(email_builder):
    """Scenario: Mismatch allowed for mailing services (e.g. Amazon SES)."""
    mime = (
        email_builder.with_sender("newsletter@startups.com")
        .with_header("Reply-To", "feedback@amazonses.com")
        .build()
    )

    email = EmailParser(mime).parse()
    detector = HeaderAnalysisDetector()
    result = detector.evaluate(email)

    if result:
        assert "Reply-To domain mismatch" not in result.description


def test_missing_all_auth(email_builder):
    """Scenario: No SPF/DKIM/DMARC present at all."""
    mime = email_builder.with_sender("anon@vpn.com").build()

    email = EmailParser(mime).parse()
    detector = HeaderAnalysisDetector()
    result = detector.evaluate(email)

    assert result is not None
    assert "No authentication headers present" in result.description
    assert result.score_impact >= 40.0
