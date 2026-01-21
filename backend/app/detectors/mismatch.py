from typing import Optional
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.base import BaseDetector
import re

class LinkMismatchDetector(BaseDetector):
    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        mismatched_links = []
        
        for link in email.urls:
            # Skip if no text content or text is just the URL itself
            if not link.text or link.text == link.url:
                continue

            # Check if text looks like a url (contains .com, http, www, etc)
            # This logic detects: <a href="bad.com">good.com</a>
            visible_text_lower = link.text.lower()
            
            # Simple heuristic: if visible text has "http" or "www" or looks like a domain
            if "http" in visible_text_lower or "www." in visible_text_lower or re.search(r'\.[a-z]{2,3}(?:/|$)', visible_text_lower):
                
                # Compare pure domains
                # This is a basic comparison. robust one requires tldextract
                try:
                    text_domain = self._extract_domain(visible_text_lower)
                    href_domain = self._extract_domain(link.url.lower())
                    
                    if text_domain and href_domain and text_domain != href_domain:
                        mismatched_links.append(f"{link.text} -> {link.url}")
                except Exception:
                    continue

        if mismatched_links:
            # Very high severity because this is almost always malicious
            return DetectorResult(
                detector_name="Link Mismatch (Hidden URL)",
                score_impact=75.0, 
                description=f"Detected mismatch between visible text and actual link destination: {', '.join(mismatched_links[:2])}"
            )
        return None

    def _extract_domain(self, url: str) -> str:
        # crude domain cleanup
        if "://" in url:
            url = url.split("://")[1]
        if "/" in url:
            url = url.split("/")[0]
        return url
