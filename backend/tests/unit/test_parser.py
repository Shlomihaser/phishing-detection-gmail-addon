from app.services.email_parser import EmailParser


def test_parse_basic_fields(email_builder):
    """
    Scenario: Standard Email Parsing
    Goal: Verify that the essential metadata (Warning headers, Sender, Subject)
    are correctly extracted from a standard multi-part MIME message.
    """
    mime = (
        email_builder.with_sender("alice@example.com")
        .with_subject("Hello World")
        .with_body("This is plain text content.")
        .build()
    )

    parser = EmailParser(mime)
    email = parser.parse()

    assert email.sender_email == "alice@example.com"
    assert email.subject == "Hello World"
    assert "plain text" in email.body_plain


def test_parse_html_only(email_builder):
    """
    Scenario: HTML-Only Email
    Goal: Verify the parser handles emails that lack a plain-text fallback.
    Some marketing emails (or sloppy tools) send only HTML. We must ensure
    we don't crash and still capture the body content.
    """
    mime = email_builder.with_body(plain="", html="<h1>Click Me</h1>").build()

    parser = EmailParser(mime)
    email = parser.parse()

    assert "<h1>Click Me</h1>" in email.body_html


def test_extract_urls(email_builder):
    """
    Scenario: URL Extraction (Mixed Content)
    Goal: Verify that we extract URLs from BOTH:
    1. The HTML body (usually the main payload in phishing).
    2. The Plain Text body (often used as a fallback).
    This ensures we don't miss a malicious link just because it was hidden in one format.
    """
    mime = email_builder.with_body(
        plain="Check this: http://plain.com",
        html="<a href='https://secure.com'>Login</a>",
    ).build()

    parser = EmailParser(mime)
    email = parser.parse()

    extracted_urls = [link.url for link in email.urls]
    assert "http://plain.com" in extracted_urls
    assert "https://secure.com" in extracted_urls


def test_extract_attachments(email_builder):
    """
    Scenario: Attachment Extraction & Binary Integrity
    Goal:
    1. Verify we detect attachments.
    2. KEY CHECK: Verify that binary content (bytes) is preserved exactly.
       Our parser handles Base64 decoding internally. If we pass raw bytes
       into the builder -> Mime encodes it -> Parser decodes it.
       The result must match the original bytes exactly (critical for magic number detection).
    """
    fake_exe = b"\x4d\x5a\x90\x00"

    mime = email_builder.with_attachment("virus.exe", fake_exe).build()

    parser = EmailParser(mime)
    email = parser.parse()

    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "virus.exe"
    assert att.content_header == fake_exe
