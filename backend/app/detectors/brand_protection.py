from typing import Optional

from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.utils.text_processing import normalize_homoglyphs, levenshtein_distance
from app.constants.brands import VALID_BRAND_DOMAINS


@DetectorRegistry.register
class BrandProtectionDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        """
        Consolidated detector for Impersonation (Name) and Typosquatting (Domain).
        """
        sender_email = email.sender_email.lower()
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        sender_name = email.sender_name.lower() if email.sender_name else ""

        # 1. Check for Sender Name Impersonation
        # (Claims to be "Microsoft" but not from microsoft.com)
        for brand in VALID_BRAND_DOMAINS.keys():
            # Does name contain "Microsoft"?
            if brand in sender_name:
                # Is the domain Valid?
                valid_list = VALID_BRAND_DOMAINS.get(brand, set())
                # Allow exact match or subdomain (support.microsoft.com)
                if not any(
                    sender_domain == v or sender_domain.endswith(f".{v}")
                    for v in valid_list
                ):
                    return DetectorResult(
                        detector_name="Brand Impersonation (Name)",
                        score_impact=75.0,
                        description=f"Sender name claims to be '{brand.title()}' but email comes from verified-unrelated domain ('{sender_domain}').",
                    )

        # 2. Check for Sender Domain Typosquatting
        # (Domain looks like "rnicrosoft.com")

        # Whitelist fast check
        # If the domain is in *ANY* valid list, we trust it purely.
        # (Optimization: We could map valid->brand, but linear scan of valid is fine for small count)
        for valid_set in VALID_BRAND_DOMAINS.values():
            if sender_domain in valid_set:
                return None

        # Normalize HOmoglyphs
        norm_domain = normalize_homoglyphs(sender_domain).split(".")[0]  # stem

        for brand in VALID_BRAND_DOMAINS.keys():
            # Distance Check
            dist = levenshtein_distance(norm_domain, brand)
            threshold = 2 if len(brand) > 5 else 1

            if 0 < dist <= threshold:
                return DetectorResult(
                    detector_name="Brand Spoofing (Domain)",
                    score_impact=80.0,
                    description=f"Sender domain '{sender_domain}' mimics protected brand '{brand}' (Dist: {dist}).",
                )

            # Substring Check ("microsoft-support")
            # Only trigger if NOT whitelisted (which passed above)
            if brand in norm_domain and brand != norm_domain:
                return DetectorResult(
                    detector_name="Brand Spoofing (Keyword)",
                    score_impact=60.0,
                    description=f"Sender domain '{sender_domain}' attempts to impersonate '{brand}' via substring.",
                )

        return None
