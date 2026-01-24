import ipaddress
from typing import Optional

from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry
from app.models.domain import Email, Link
from app.models.risk import DetectorResult
from app.utils.url_parser import extract_domain
from app.constants.links import SUSPICIOUS_TLDS, SHORTENER_DOMAINS
from app.constants.regex import URL_LIKE_PATTERN
from app.constants.scoring import LinkScores


@DetectorRegistry.register
class MaliciousLinkDetector(BaseDetector):
    """Detects malicious URLs through domain analysis and deception patterns."""

    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        """Analyze all URLs in email for security threats.
        
        Checks for: raw IP addresses, link masking, URL shorteners, suspicious TLDs.
        """
        flagged = {}
        max_score = 0.0

        for link in email.urls:
            reasons, score = self._analyze_link(link)
            if reasons:
                flagged[link.url] = reasons
                max_score = max(max_score, score)

        return self._build_result(flagged, max_score) if flagged else None

    def _analyze_link(self, link: Link) -> tuple[list[str], float]:
        reasons = []
        max_score = 0.0

        checks = [
            self._check_ip_address(link.url),
            self._check_link_masking(link),
            self._check_url_shortener(link.url),
            self._check_suspicious_tld(link.url),
        ]

        for score, reason in checks:
            if reason:
                reasons.append(reason)
                max_score = max(max_score, score)

        return reasons, max_score

    def _check_ip_address(self, url: str) -> tuple[float, Optional[str]]:
        try:
            clean_url = url.replace("https://", "").replace("http://", "")
            host = clean_url.split("/")[0].split(":")[0].strip("[]")
            ip = ipaddress.ip_address(host)
            return LinkScores.IP_ADDRESS, f"destination is a raw IP address ({ip})"
        except ValueError:
            return 0.0, None

    def _check_link_masking(self, link: Link) -> tuple[float, Optional[str]]:
        if not link.text or not URL_LIKE_PATTERN.search(link.text.strip()):
            return 0.0, None

        text_ext = extract_domain(link.text.strip())
        url_ext = extract_domain(link.url)

        text_domain = text_ext.top_domain_under_public_suffix
        url_domain = url_ext.top_domain_under_public_suffix

        if not text_domain or not url_domain:
            return 0.0, None

        if text_domain.lower() != url_domain.lower():
            return (
                LinkScores.LINK_MASKING,
                f"link masking detected (text says '{text_domain}' but goes to '{url_domain}')",
            )
        return 0.0, None

    def _check_url_shortener(self, url: str) -> tuple[float, Optional[str]]:
        ext = extract_domain(url)
        full_domain = f"{ext.domain}.{ext.suffix}".lower()

        if full_domain in SHORTENER_DOMAINS:
            return LinkScores.URL_SHORTENER, f"hidden behind URL shortener ({full_domain})"
        return 0.0, None

    def _check_suspicious_tld(self, url: str) -> tuple[float, Optional[str]]:
        ext = extract_domain(url)

        if ext.suffix.lower() in SUSPICIOUS_TLDS:
            return (
                LinkScores.SUSPICIOUS_TLD,
                f"uses suspicious Top-Level Domain (.{ext.suffix})",
            )
        return 0.0, None

    def _build_result(
        self, flagged: dict[str, list[str]], max_score: float
    ) -> DetectorResult:
        issue_details = [f"Link '{url}': {', '.join(issues)}" for url, issues in flagged.items()]
        return DetectorResult(
            detector_name="Malicious Link Detector",
            score_impact=max_score,
            description="Suspicious links detected: " + "; ".join(issue_details),
        )
