from app.detectors.attachment_detector import HarmfulAttachmentDetector
from app.models.domain import Email, Attachment, AuthHeaders
import logging

logging.getLogger("app.detectors.attachment_detector").setLevel(logging.ERROR)


def test_attachment_dangerous_extension():
    """
    Scenario: Explicitly Dangerous Extension.
    Attack: Sender sends 'malware.exe'.
    Expected: Detector flags it immediately as high risk (100).
    """
    detector = HarmfulAttachmentDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[],
        attachments=[Attachment(filename="malware.exe", content_header=b"MZ")],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact == 100.0
    assert "malicious file type" in result.description


def test_attachment_double_extension():
    """
    Scenario: Double Extension Trick.
    Attack: 'invoice.pdf.exe' (Windows hides the .exe, user thinks it's a PDF).
    Expected: Detector identifies the mismatch between the fake extension (.pdf) and real extension (.exe).
    """
    detector = HarmfulAttachmentDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[],
        attachments=[Attachment(filename="invoice.pdf.exe", content_header=b"MZ")],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact == 100.0
    assert "double extension" in result.description


def test_attachment_mime_spoofing():
    """
    Scenario: Content Spoofing (Magic Number Mismatch).
    Attack: File is named 'safe.txt' but content is actually an executable binary (MZ header).
    Expected: Detector uses 'magic' library to see true type vs declared extension.
    """
    # 'MZ' is the magic header for Windows Executables (DLL/EXE)
    exe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"

    detector = HarmfulAttachmentDetector()
    email = Email(
        sender_email="test@test.com",
        sender_name="Test",
        reply_to=None,
        urls=[],
        attachments=[Attachment(filename="safe.txt", content_header=exe_header)],
        auth_results=AuthHeaders(),
        headers={},
    )

    result = detector.evaluate(email)

    assert result is not None
    assert result.score_impact == 75.0
    assert "does not match extension" in result.description
