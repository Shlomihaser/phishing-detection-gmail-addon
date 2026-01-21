import re
import mailparser
from typing import List, Dict
from datetime import datetime
from email.utils import parseaddr
from app.models.domain import Email, AuthHeaders, Link
from app.models.email_request import EmailRequest

class EmailParser:
    """
    Parses raw email content using `mail-parser` to extract structured data 
    (headers, body, URLs, authentication status) for phishing analysis.
    """
    def __init__(self, email_request: EmailRequest):
        self.email_request = email_request
        # mail-parser handles complex decoding and multipart splitting automatically
        self.mail = mailparser.parse_from_string(email_request.rawContent)

    def parse(self) -> Email:
        """
        Main execution pipeline.
        Returns a populated Email object with normalized data.
        """
        auth_headers = self._extract_auth_headers()
        sender_name, sender_email = parseaddr(self.email_request.sender)
        
        try:
            creation_date = datetime.fromisoformat(self.email_request.date.replace("Z", "+00:00"))
        except ValueError:
            creation_date = None

        text_content = "\n".join(self.mail.text_plain) if self.mail.text_plain else self.mail.body or ""
        html_content = "\n".join(self.mail.text_html) if self.mail.text_html else ""

        return Email(
            message_id=self.email_request.messageId,
            sender_name=sender_name,
            sender_email=sender_email,
            reply_to=self._get_reply_to_address(),
            subject=self.email_request.subject,
            creation_date=creation_date,
            body_text=text_content, 
            urls=self._extract_urls(text_content, html_content),
            email_addresses=self._extract_emails(text_content),
            auth_results=auth_headers,
            headers=self._get_important_headers()
        )

    def _get_reply_to_address(self) -> str | None:
        """
        Safely extracts the Reply-To address.
        mail-parser often returns this as a list of tuples: [('Name', 'email@domain.com')]
        """
        reply_to = self.mail.headers.get("Reply-To")
        
        if not reply_to:
            return None
            
        # Handle list case (e.g. [('Name', 'email')] or ['email'])
        if isinstance(reply_to, list):
            if not reply_to:
                return None
            first_item = reply_to[0]
            if isinstance(first_item, tuple):
                # Return the email part (2nd element)
                return first_item[1]
            return str(first_item)
            
        return str(reply_to)

    def _extract_auth_headers(self) -> AuthHeaders:
        """
        Parses `Authentication-Results` to check for SPF/DKIM/DMARC passes.
        """
        # Lowercase to handle case-insensitive "PASS" or "pass" values
        auth_results = self.mail.headers.get("Authentication-Results", "").lower()
        spf = dkim = dmarc = None

        if auth_results:
            if "spf=pass" in auth_results: spf = "pass"
            elif "spf=fail" in auth_results: spf = "fail"
            
            if "dkim=pass" in auth_results: dkim = "pass"
            elif "dkim=fail" in auth_results: dkim = "fail"
            
            if "dmarc=pass" in auth_results: dmarc = "pass"
            elif "dmarc=fail" in auth_results: dmarc = "fail"

        if not spf:
            rec_spf = self.mail.headers.get("Received-SPF", "").lower()
            if "pass" in rec_spf: spf = "pass"
            elif "fail" in rec_spf: spf = "fail"
        
        return AuthHeaders(spf=spf, dkim=dkim, dmarc=dmarc)

    def _extract_urls(self, text: str, html: str) -> List[Link]:
        """
        Extracts URLs from both plain text and HTML.
        Returns a list of Link objects (containing url and visible text).
        """
        links = []
        seen_urls = set()

        # 1. HTML Links (Best source for text)
        # Regex to capture <a ... href="...">TEXT</a>
        # This is a basic heuristic regex. Ideally use BS4 if accuracy is critical.
        # Capture group 1: URL, Capture group 2: Visible Text
        html_link_pattern = r'<a\s+(?:[^>]*?\s+)?href=["\'](.*?)["\'][^>]*>(.*?)</a>'
        for match in re.finditer(html_link_pattern, html, re.IGNORECASE | re.DOTALL):
            url = match.group(1).strip()
            text_content = match.group(2).strip()
            # Clean HTML tags from text (e.g. bold tags inside link)
            clean_text = re.sub(r'<[^>]+>', '', text_content).strip()
            
            if url:
                links.append(Link(url=url, text=clean_text))
                seen_urls.add(url)

        # 2. Plain Text / Remaining Links (No specific text)
        text_url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*[^.,;!?)\]\s]'
        
        # Combine text and remaining HTML hrefs
        all_text_matches = re.findall(text_url_pattern, text)
        href_pattern = r'href=[\'"]?(https?://[^\'" >]+)' 
        all_href_matches = re.findall(href_pattern, html)
        
        for url in all_text_matches + all_href_matches:
            clean_url = url.strip('.,;!?) \n\r')
            if clean_url not in seen_urls:
                links.append(Link(url=clean_url, text=None))
                seen_urls.add(clean_url)
                
        return links

    def _extract_emails(self, text: str) -> List[str]:
        email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        emails = re.findall(email_pattern, text)
        return list(set(emails))

    def _get_important_headers(self) -> Dict[str, str]:
        keys = ["Subject", "Received", "X-Mailer", "Return-Path", "Content-Type"]
        return {k: str(self.mail.headers.get(k, "")) for k in keys if k in self.mail.headers}