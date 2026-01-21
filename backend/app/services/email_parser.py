import email
from email.message import Message
import re
from typing import List, Dict, Optional
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from ..models.internal import ParsedEmail, AuthHeaders

from ..models.email_request import EmailRequest

class EmailParser:
    def __init__(self, email_request: EmailRequest):
        self.email_request = email_request
        self.msg = email.message_from_string(email_request.rawContent)

    def parse(self) -> ParsedEmail:
        """
        Main method to execute the parsing pipeline.
        Returns a populated ParsedEmail object.
        """
        auth_headers = self._extract_auth_headers()
        # metadata = self._extract_metadata() # Fallback or deprecated if we rely on request
        # But we still need sender separation (name/email) from the string in request
        
        # Parse sender from request string "Name <email>"
        sender_name, sender_email = parseaddr(self.email_request.sender)
        
        # Parse date from request ISO string
        try:
            creation_date = datetime.fromisoformat(self.email_request.date.replace("Z", "+00:00"))
        except ValueError:
            creation_date = datetime.utcnow()

        body_content = self._extract_body()
        
        return ParsedEmail(
            message_id=self.email_request.messageId,
            sender_name=sender_name,
            sender_email=sender_email,
            reply_to=self.msg.get("Reply-To"), # Keep extracting this from raw as it might not be in request top-level
            subject=self.email_request.subject,
            creation_date=creation_date,
            body_text=self.email_request.body, # The request already has specific body text
            urls=self._extract_urls(self.email_request.body, body_content["html"]),
            email_addresses=self._extract_emails(self.email_request.body),
            auth_results=auth_headers,
            headers=self._get_important_headers()
        )

    def _extract_auth_headers(self) -> AuthHeaders:
        """
        Extracts raw authentication statuses (pass, fail, etc.)
        Prioritizes Authentication-Results header, then falls back to specific headers.
        """
        auth_results = self.msg.get("Authentication-Results", "")
        spf = None
        dkim = None
        dmarc = None

        # Simple extraction from Authentication-Results (this is a basic implementation)
        # Real-world parsing of this header can be complex as it varies by provider.
        if auth_results:
            if "spf=pass" in auth_results: spf = "pass"
            elif "spf=fail" in auth_results: spf = "fail"
            
            if "dkim=pass" in auth_results: dkim = "pass"
            elif "dkim=fail" in auth_results: dkim = "fail"
            
            if "dmarc=pass" in auth_results: dmarc = "pass"
            elif "dmarc=fail" in auth_results: dmarc = "fail"

        # Fallbacks if not found
        if not spf:
            rec_spf = self.msg.get("Received-SPF", "").lower()
            if "pass" in rec_spf: spf = "pass"
            elif "fail" in rec_spf: spf = "fail"

        # Note: DKIM extraction from DKIM-Signature tells us presence, not validity, 
        # unless we do cryptographic verification. Here we stick to what the receiving server said.
        
        return AuthHeaders(spf=spf, dkim=dkim, dmarc=dmarc)

    def _extract_metadata(self) -> Dict:
        metadata = {}
        
        # Message ID
        metadata["message_id"] = self.msg.get("Message-ID", "").strip()

        # Date
        date_header = self.msg.get("Date")
        if date_header:
            try:
                metadata["date"] = parsedate_to_datetime(date_header)
            except Exception:
                metadata["date"] = datetime.utcnow()
        else:
            metadata["date"] = datetime.utcnow()

        # Sender
        from_header = self.msg.get("From", "")
        name, addr = parseaddr(from_header)
        metadata["sender_name"] = name
        metadata["sender_email"] = addr

        # Reply-To
        reply_header = self.msg.get("Reply-To", "")
        _, reply_addr = parseaddr(reply_header)
        metadata["reply_to"] = reply_addr if reply_addr else None

        return metadata

    def _extract_body(self) -> Dict[str, str]:
        """
        Extracts plain text and HTML content from the email.
        """
        text_content = ""
        html_content = ""

        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if "attachment" in content_disposition:
                    continue

                payload = part.get_payload(decode=True)
                if not payload:
                    continue

                # robust decoding
                charset = part.get_content_charset() or "utf-8"
                try:
                    decoded = payload.decode(charset, errors="replace")
                except LookupError:
                    decoded = payload.decode("utf-8", errors="replace")

                if content_type == "text/plain":
                    text_content += decoded
                elif content_type == "text/html":
                    html_content += decoded
        else:
            # Not multipart
            payload = self.msg.get_payload(decode=True)
            if payload:
                charset = self.msg.get_content_charset() or "utf-8"
                try:
                    text_content = payload.decode(charset, errors="replace")
                except LookupError:
                    text_content = payload.decode("utf-8", errors="replace")

        return {"text": text_content, "html": html_content}

    def _extract_urls(self, text: str, html: str) -> List[str]:
        """
        Extracts URLs from both text and HTML content.
        """
        urls = set()
        
        # Regex for URLs in text
        # Matches http/https/ftp and standard domain patterns
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        urls.update(re.findall(url_pattern, text))
        
        # Simple extraction from HTML hrefs without heavy dependencies if possible
        # For now, regex on HTML is acceptable for a lightweight parser
        html_url_pattern = r'href=[\'"]?(https?://[^\'" >]+)'
        urls.update(re.findall(html_url_pattern, html))

        return list(urls)

    def _extract_emails(self, text: str) -> List[str]:
        """
        Extracts email addresses from the body text.
        """
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return list(set(re.findall(email_pattern, text)))

    def _get_important_headers(self) -> Dict[str, str]:
        """
        Returns a dictionary of other useful headers for heuristic analysis.
        """
        keys = ["Subject", "Received", "X-Mailer", "Return-Path", "Content-Type"]
        return {k: self.msg.get(k, "") for k in keys if self.msg.get(k)}
