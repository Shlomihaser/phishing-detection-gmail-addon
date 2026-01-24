import ipaddress
import tldextract

from typing import Optional
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry
from app.constants.links import SUSPICIOUS_TLDS, SHORTENER_DOMAINS
from app.constants.regex import URL_LIKE_PATTERN


@DetectorRegistry.register
class MaliciousLinkDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        flagged_links = {}
        max_risk_score = 0.0
        
        for link in email.urls:
            url = link.url
            text = link.text
            reasons = []
            
            # --- 1. IP Address Check (Score: 40) ---
            ext = tldextract.extract(url)            
            try:
                # Remove protocol and get host
                clean_url = url.replace('https://', '').replace('http://', '')
                host = clean_url.split('/')[0].split(':')[0]
                
                # Remove brackets for IPv6 (e.g., [::1])
                host = host.strip('[]')
                # This catches: IPv4, IPv6, Hex IPs, Decimal IPs, Octal IPs
                ip = ipaddress.ip_address(host)
                reasons.append(f"destination is a raw IP address ({ip})")
                max_risk_score = max(max_risk_score, 40.0)
            except ValueError:
                # Not an IP address - this is normal/expected for domain names
                pass

            # --- 2. Link Masking / Mismatch (Score: 50) ---
            if text and URL_LIKE_PATTERN.search(text.strip()):
                # Extract domain from the visible text
                text_ext = tldextract.extract(text.strip())
                url_ext = tldextract.extract(url)
                
                # We compare registered_domain (e.g., 'google.com' from 'drive.google.com')
                if text_ext.registered_domain and url_ext.registered_domain:
                    # If domains differ, it's a mismatch
                    if text_ext.registered_domain.lower() != url_ext.registered_domain.lower():
                        reasons.append(f"link masking detected (text says '{text_ext.registered_domain}' but goes to '{url_ext.registered_domain}')")
                        max_risk_score = max(max_risk_score, 50.0)
            
            # --- 3. URL Shorteners (Score: 25) ---
            # domain + suffix check (e.g. bit.ly)
            full_domain = f"{ext.domain}.{ext.suffix}".lower()
            if full_domain in SHORTENER_DOMAINS:
                reasons.append(f"hidden behind URL shortener ({full_domain})")
                max_risk_score = max(max_risk_score, 25.0)

            # --- 4. Suspicious TLDs (Score: 20) ---
            if ext.suffix.lower() in SUSPICIOUS_TLDS:
                reasons.append(f"uses suspicious Top-Level Domain (.{(ext.suffix)})")
                max_risk_score = max(max_risk_score, 20.0)

            # --- 5. Insecure Protocol (Score: 15) ---
            if url.lower().startswith("http://"):
                reasons.append("insecure HTTP protocol")
                max_risk_score = max(max_risk_score, 15.0)

            if reasons:
                flagged_links[url] = reasons

        if not flagged_links:
            return None
            
        issue_details = []
        for url, issues in flagged_links.items():
            issue_details.append(f"Link '{url}': {', '.join(issues)}")

        return DetectorResult(
            detector_name="Malicious Link Detector",
            score_impact=max_risk_score,
            description="Suspicious links detected: " + "; ".join(issue_details)
        )
