import logging
import os
import magic

from typing import Optional, NamedTuple

from app.detectors.core.base import BaseDetector
from app.detectors.core.registry import DetectorRegistry
from app.models.domain import Email, Attachment
from app.models.risk import DetectorResult
from app.constants.file_defs import FILE_DEFINITIONS, FileType
from app.constants.scoring import AttachmentScores

logger = logging.getLogger(__name__)


class AttachmentAnalysis(NamedTuple):
    name: str
    reasons: list[str]
    score: float


@DetectorRegistry.register
class HarmfulAttachmentDetector(BaseDetector):
    """Detects malicious attachments through extension, MIME type, and content analysis."""

    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        """Analyze all attachments for security threats.
        
        Checks for: dangerous extensions, hidden executables, double extensions,
        MIME mismatches, and suspicious unnamed attachments.
        """
        flagged = {}
        max_score = 0.0

        for index, attachment in enumerate(email.attachments):
            result = self._analyze_attachment(attachment, index)
            if result:
                flagged[result.name] = result.reasons
                max_score = max(max_score, result.score)

        return self._build_result(flagged, max_score) if flagged else None

    def _analyze_attachment(
        self, attachment: Attachment, index: int
    ) -> Optional[AttachmentAnalysis]:
        detected_mime = self._detect_mime_type(attachment)
        ext, fake_ext, file_def = self._parse_filename(attachment)
        is_executable = self._is_executable_mime(detected_mime)

        reasons = []
        max_score = 0.0

        if attachment.filename:
            checks = [
                self._check_hidden_executable(detected_mime, ext, is_executable),
                self._check_dangerous_extension(file_def, ext),
                self._check_missing_extension(ext, detected_mime),
                self._check_double_extension(fake_ext, ext, file_def),
                self._check_mime_mismatch(detected_mime, ext, file_def, is_executable),
            ]
        else:
            if self._is_safe_inline_content(detected_mime):
                return None
            checks = [(AttachmentScores.UNNAMED_SUSPICIOUS, "unnamed suspicious attachment")]

        for score, reason in checks:
            if reason:
                reasons.append(reason)
                max_score = max(max_score, score)

        if not reasons:
            return None

        name = attachment.filename or f"unnamed_attachment_{index}"
        return AttachmentAnalysis(name=name, reasons=reasons, score=max_score)

    def _detect_mime_type(self, attachment: Attachment) -> str:
        if not attachment.content_header:
            return "application/octet-stream"
        try:
            return magic.from_buffer(attachment.content_header, mime=True)
        except Exception as e:
            logger.warning(f"Magic file detection failed: {e}")
            return "application/octet-stream"

    def _parse_filename(self, attachment: Attachment) -> tuple[str, str, Optional[dict]]:
        if not attachment.filename:
            return "", "", None

        filename = attachment.filename.lower()
        name, ext_with_dot = os.path.splitext(filename)
        ext = ext_with_dot.lstrip(".") if ext_with_dot else ""
        fake_ext = name.split(".")[-1] if "." in name else ""
        file_def = FILE_DEFINITIONS.get(ext)

        return ext, fake_ext, file_def

    def _is_executable_mime(self, mime: str) -> bool:
        return mime in ("application/x-dosexec", "application/x-msdownload")

    def _is_safe_inline_content(self, mime: str) -> bool:
        return mime.startswith(("image/", "text/"))

    def _check_hidden_executable(
        self, detected_mime: str, ext: str, is_executable: bool
    ) -> tuple[float, Optional[str]]:
        if is_executable and ext not in ("exe", "msi"):
            return (
                AttachmentScores.HIDDEN_EXECUTABLE,
                f"hidden executable content detected ({detected_mime})",
            )
        return 0.0, None

    def _check_dangerous_extension(
        self, file_def: Optional[dict], ext: str
    ) -> tuple[float, Optional[str]]:
        if file_def and file_def["type"] == FileType.DANGEROUS:
            return AttachmentScores.MALICIOUS_FILE, f"malicious file type ({ext})"
        return 0.0, None

    def _check_missing_extension(
        self, ext: str, detected_mime: str
    ) -> tuple[float, Optional[str]]:
        if not ext and not self._is_safe_inline_content(detected_mime):
            return AttachmentScores.MISSING_EXTENSION, "missing file extension"
        return 0.0, None

    def _check_double_extension(
        self, fake_ext: str, ext: str, file_def: Optional[dict]
    ) -> tuple[float, Optional[str]]:
        fake_def = FILE_DEFINITIONS.get(fake_ext)
        if fake_def and fake_def["type"] == FileType.SAFE:
            if not file_def or file_def["type"] != FileType.SAFE:
                return (
                    AttachmentScores.DOUBLE_EXTENSION,
                    f"deceptive double extension (.{fake_ext}.{ext})",
                )
        return 0.0, None

    def _check_mime_mismatch(
        self,
        detected_mime: str,
        ext: str,
        file_def: Optional[dict],
        is_executable: bool,
    ) -> tuple[float, Optional[str]]:
        if not file_def or not file_def.get("mime"):
            return 0.0, None

        expected_mime = file_def["mime"]
        if self._is_mime_match_valid(detected_mime, expected_mime, ext):
            return 0.0, None

        if is_executable:
            return AttachmentScores.HIDDEN_EXECUTABLE, None
        return (
            AttachmentScores.MIME_MISMATCH,
            f"file content ({detected_mime}) does not match extension (expected {expected_mime})",
        )

    def _is_mime_match_valid(self, detected: str, expected: str, ext: str) -> bool:
        if detected == expected:
            return True

        file_def = FILE_DEFINITIONS.get(ext)
        if file_def:
            allowed_alt = file_def.get("alt", [])
            if detected in allowed_alt:
                return True

        return False

    def _build_result(
        self, flagged: dict[str, list[str]], max_score: float
    ) -> DetectorResult:
        issue_details = [f"{fname}: {', '.join(issues)}" for fname, issues in flagged.items()]
        return DetectorResult(
            detector_name="Harmful Attachment Detector",
            score_impact=max_score,
            description="Suspicious attachments detected: " + "; ".join(issue_details),
        )
