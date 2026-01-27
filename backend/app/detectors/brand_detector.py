from typing import Optional

from app.detectors.core.base import BaseDetector
from app.detectors.core.registry import DetectorRegistry
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.utils.text_processing import normalize_homoglyphs, levenshtein_distance
from app.constants.brands import VALID_BRAND_DOMAINS


@DetectorRegistry.register
class BrandProtectionDetector(BaseDetector):
    """Protects against brand impersonation and domain typosquatting attacks."""

    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        """Detect sender impersonation of known brands.
        
        Checks for: name impersonation, domain typosquatting, homoglyph attacks.
        """
        sender_domain, sender_name = self._extract_sender_info(email)

        if result := self._check_name_impersonation(sender_name, sender_domain):
            return result

        if self._is_whitelisted_domain(sender_domain):
            return None

        return self._check_typosquatting(sender_domain)

    def _extract_sender_info(self, email: Email) -> tuple[str, str]:
        sender_email = email.sender_email.lower()
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        sender_name = email.sender_name.lower() if email.sender_name else ""
        return sender_domain, sender_name

    def _check_name_impersonation(
        self, sender_name: str, sender_domain: str
    ) -> Optional[DetectorResult]:
        for brand, valid_domains in VALID_BRAND_DOMAINS.items():
            if brand not in sender_name:
                continue

            is_valid_domain = any(
                sender_domain == v or sender_domain.endswith(f".{v}")
                for v in valid_domains
            )

            if not is_valid_domain:
                return DetectorResult(
                    detector_name="Brand Impersonation (Name)",
                    score_impact=75.0,
                    description=f"Sender name claims to be '{brand.title()}' but email comes from verified-unrelated domain ('{sender_domain}').",
                )
        return None

    def _is_whitelisted_domain(self, sender_domain: str) -> bool:
        for valid_set in VALID_BRAND_DOMAINS.values():
            if sender_domain in valid_set:
                return True
        return False

    def _check_typosquatting(self, sender_domain: str) -> Optional[DetectorResult]:
        norm_domain = normalize_homoglyphs(sender_domain).split(".")[0]

        for brand in VALID_BRAND_DOMAINS.keys():
            if result := self._check_distance_typosquatting(sender_domain, norm_domain, brand):
                return result

            if result := self._check_substring_spoofing(sender_domain, norm_domain, brand):
                return result

        return None

    def _check_distance_typosquatting(
        self, sender_domain: str, norm_domain: str, brand: str
    ) -> Optional[DetectorResult]:
        dist = levenshtein_distance(norm_domain, brand)
        threshold = 2 if len(brand) > 5 else 1

        if 0 < dist <= threshold:
            return DetectorResult(
                detector_name="Brand Spoofing (Domain)",
                score_impact=80.0,
                description=f"Sender domain '{sender_domain}' mimics protected brand '{brand}' (Dist: {dist}).",
            )
        return None

    def _check_substring_spoofing(
        self, sender_domain: str, norm_domain: str, brand: str
    ) -> Optional[DetectorResult]:
        if brand in norm_domain and brand != norm_domain:
            return DetectorResult(
                detector_name="Brand Spoofing (Keyword)",
                score_impact=60.0,
                description=f"Sender domain '{sender_domain}' attempts to impersonate '{brand}' via substring.",
            )
        return None
