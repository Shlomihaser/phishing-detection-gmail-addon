from typing import Optional

from app.detectors.core.base import BaseDetector
from app.detectors.core.registry import DetectorRegistry
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.utils.url_parser import extract_domain
from app.constants.allowed_hosts import MAILING_SERVICE_DOMAINS


@DetectorRegistry.register
class HeaderAnalysisDetector(BaseDetector):
    """Analyzes email headers for authentication failures and identity mismatches."""

    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        """Check email authentication (SPF/DKIM/DMARC) and sender identity consistency.
        
        Detects: auth failures, Reply-To mismatches, Return-Path mismatches.
        """
        reasons = []
        max_score = 0.0

        auth_reasons, auth_score = self._check_authentication(email)
        if auth_reasons:
            reasons.extend(auth_reasons)
            max_score = max(max_score, auth_score)

        reply_reason, reply_score = self._check_reply_to_mismatch(email)
        if reply_reason:
            reasons.append(reply_reason)
            max_score = max(max_score, reply_score)

        return_reason, return_score = self._check_return_path_mismatch(email)
        if return_reason:
            reasons.append(return_reason)
            max_score = max(max_score, return_score)

        if not reasons:
            return None

        return DetectorResult(
            detector_name="Header analysis",
            score_impact=max_score,
            description="Authentication/Identity issues: " + "; ".join(reasons),
        )

    def _check_authentication(self, email: Email) -> tuple[list[str], float]:
        if not email.auth_results:
            return [], 0.0

        spf = email.auth_results.spf
        dkim = email.auth_results.dkim
        dmarc = email.auth_results.dmarc

        if not spf and not dkim and not dmarc:
            return ["No authentication headers present (SPF/DKIM/DMARC missing)"], 40.0

        reasons = []
        max_score = 0.0

        spf_reason, spf_score = self._evaluate_spf(spf)
        if spf_reason:
            reasons.append(spf_reason)
            max_score = max(max_score, spf_score)

        dkim_reason, dkim_score = self._evaluate_dkim(dkim)
        if dkim_reason:
            reasons.append(dkim_reason)
            max_score = max(max_score, dkim_score)

        dmarc_reason, dmarc_score = self._evaluate_dmarc(dmarc)
        if dmarc_reason:
            reasons.append(dmarc_reason)
            max_score = max(max_score, dmarc_score)

        return reasons, max_score

    def _evaluate_spf(self, spf: Optional[str]) -> tuple[Optional[str], float]:
        if not spf:
            return None, 0.0
        if spf == "fail":
            return "SPF authentication failed", 100.0
        if spf in ("softfail", "neutral"):
            return f"SPF result is weak ({spf})", 40.0
        return None, 0.0

    def _evaluate_dkim(self, dkim: Optional[str]) -> tuple[Optional[str], float]:
        if not dkim:
            return None, 0.0
        if dkim == "fail":
            return "DKIM signature invalid", 100.0
        if dkim in ("neutral", "policy"):
            return f"DKIM result is weak ({dkim})", 30.0
        return None, 0.0

    def _evaluate_dmarc(self, dmarc: Optional[str]) -> tuple[Optional[str], float]:
        if not dmarc:
            return None, 0.0
        if dmarc == "fail":
            return "DMARC policy failed (domain owner rejects this email)", 100.0
        if dmarc in ("none", "quarantine"):
            return f"DMARC policy is {dmarc}", 25.0
        return None, 0.0

    def _check_reply_to_mismatch(self, email: Email) -> tuple[Optional[str], float]:
        if not email.reply_to or not email.sender_email:
            return None, 0.0

        sender_domain = self._get_registered_domain(email.sender_email)
        reply_domain = self._get_registered_domain(email.reply_to)

        if not sender_domain or not reply_domain:
            return None, 0.0

        if sender_domain != reply_domain and reply_domain not in MAILING_SERVICE_DOMAINS:
            return (
                f"Reply-To domain mismatch (From: {sender_domain}, Reply-To: {reply_domain})",
                60.0,
            )
        return None, 0.0

    def _check_return_path_mismatch(self, email: Email) -> tuple[Optional[str], float]:
        if not email.return_path or not email.sender_email:
            return None, 0.0

        sender_domain = self._get_registered_domain(email.sender_email)
        return_domain = self._get_registered_domain(email.return_path)

        if not sender_domain or not return_domain:
            return None, 0.0

        if sender_domain != return_domain and return_domain not in MAILING_SERVICE_DOMAINS:
            return (
                f"Return-Path mismatch (From: {sender_domain}, Envelope: {return_domain})",
                30.0,
            )
        return None, 0.0

    def _get_registered_domain(self, value: str) -> str:
        ext = extract_domain(value)
        return ext.registered_domain.lower() if ext.registered_domain else ""
