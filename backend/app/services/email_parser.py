import re
import mailparser
from typing import List, Dict
from datetime import datetime
from email.utils import parseaddr
from ..models.internal import Email, AuthHeaders
from ..models.email_request import EmailRequest

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
            reply_to=self.mail.headers.get("Reply-To"),
            subject=self.email_request.subject,
            creation_date=creation_date,
            body_text=text_content, 
            urls=self._extract_urls(text_content, html_content),
            email_addresses=self._extract_emails(text_content),
            auth_results=auth_headers,
            headers=self._get_important_headers()
        )

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

    def _extract_urls(self, text: str, html: str) -> List[str]:
        urls = set()
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*[^.,;!?)\]\s]'
        urls.update(re.findall(url_pattern, text))

        html_url_pattern = r'href=[\'"]?(https?://[^\'" >]+)'
        found_html_urls = re.findall(html_url_pattern, html)

        for url in found_html_urls:
            urls.add(url.strip('.,;!?) \n\r'))

        return list(urls)

    def _extract_emails(self, text: str) -> List[str]:
        email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        emails = re.findall(email_pattern, text)
        return list(set(emails))

    def _get_important_headers(self) -> Dict[str, str]:
        keys = ["Subject", "Received", "X-Mailer", "Return-Path", "Content-Type"]
        return {k: str(self.mail.headers.get(k, "")) for k in keys if k in self.mail.headers}