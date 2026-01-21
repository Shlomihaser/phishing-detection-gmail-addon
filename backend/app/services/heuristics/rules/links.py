import re
from typing import Optional
from ....models.internal import Email
from ....models.risk import HeuristicDetail
from ..base import HeuristicRule

class SuspiciousLinkRule(HeuristicRule):
    def __init__(self):
        # Common URL shorteners used to hide destinations
        self.shorteners = {
            "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", 
            "is.gd", "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "tr.im"
        }

    def evaluate(self, email: Email) -> Optional[HeuristicDetail]:
        suspicious_count = 0
        reasons = []

        # Regex patterns for raw IPs and obfuscation
        # IPv4: 192.168.1.1
        ipv4_pattern = r'https?://(?:\d{1,3}\.){3}\d{1,3}'
        # IPv6: [2001:db8::1] - Basic check for bracketed IPv6 in URL
        ipv6_pattern = r'https?://\[[a-fA-F0-9:]+\]' 
        # Hex/Octal: 0x7f000001 or 0177.0.0.1 (leading zeros check is complex, focusing on 0x)
        hex_ip_pattern = r'https?://0x[a-fA-F0-9]+'
        
        for url in email.urls:
            url_lower = url.lower()
            
            # Check 1: Raw IP or Obfuscated IP
            if (re.search(ipv4_pattern, url) or 
                re.search(ipv6_pattern, url) or 
                re.search(hex_ip_pattern, url_lower)):
                suspicious_count += 1
                reasons.append(f"IP/Obfuscated URL: {url}")
                continue

            # Check 2: URL Shorteners
            domain_part = url_lower.split("://")[-1].split("/")[0]
            domain = domain_part.split(":")[0]
            
            if domain in self.shorteners:
                suspicious_count += 1
                reasons.append(f"URL Shortener: {url}")
            
        if suspicious_count > 0:
             return HeuristicDetail(
                rule_name="Suspicious Links",
                score_impact=20.0 * suspicious_count,
                description=f"Found {suspicious_count} suspicious link(s): {', '.join(reasons[:3])}"
            )
        return None
