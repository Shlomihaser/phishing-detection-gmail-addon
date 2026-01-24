import base64
import logging
from email.utils import parseaddr
from typing import Dict, List, Optional

import authres
import mailparser
from bs4 import BeautifulSoup

from app.constants.regex import URL_PATTERN
from app.exceptions import EmailParsingError
from app.models.domain import Attachment, AuthHeaders, Email, Link

logger = logging.getLogger(__name__)


class EmailParser:
    def __init__(self, mime_content: str):
        try:
            self.mail = mailparser.parse_from_string(mime_content)
        except Exception as e:
            logger.error(f"Failed to parse email MIME: {e}")
            raise EmailParsingError(f"Could not parse email content: {str(e)}")

    def parse(self) -> Email:
        return Email(
            sender_name=self._extract_sender_name(),
            sender_email=self._extract_sender_email(),
            reply_to=self._extract_reply_to(),
            subject=self.mail.subject,
            body_plain=self._extract_body_plain(),
            body_html=self._extract_body_html(),
            urls=self._extract_urls(),
            attachments=self._extract_attachments(),
            auth_results=self._extract_auth_results(),
            headers=self._extract_headers(),
            return_path=self._extract_header("Return-Path"),
            x_mailer=self._extract_header("X-Mailer"),
            message_id=self._extract_header("Message-ID"),
        )

    def _extract_sender_name(self) -> Optional[str]:
        if self.mail.from_ and len(self.mail.from_) > 0:
            name = self.mail.from_[0][0]
            return name
        return None

    def _extract_sender_email(self) -> str:
        if self.mail.from_ and len(self.mail.from_) > 0:
            email = self.mail.from_[0][1]
            return email
        return None

    def _extract_reply_to(self) -> Optional[str]:
        reply_to = self.mail.headers.get("Reply-To")
        if reply_to:
            _, email = parseaddr(reply_to)
            return email
        return None

    def _extract_body_plain(self) -> Optional[str]:
        if self.mail.text_plain:
            return "\n".join(self.mail.text_plain)
        return None

    def _extract_body_html(self) -> Optional[str]:
        if self.mail.text_html:
            return "\n".join(self.mail.text_html)
        return None

    def _extract_urls(self) -> List[Link]:
        """Extract all URLs from the email body (plain text and HTML)."""
        links_map: Dict[str, Optional[str]] = {}

        # 1. Extract from HTML (Rich extraction with anchor text)
        html_content = self._extract_body_html()
        if html_content:
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    text = a_tag.get_text(separator=" ", strip=True) or None

                    if href.startswith(("http://", "https://")):
                        clean_href = href.rstrip(".,;:!?")
                        links_map[clean_href] = text
            except Exception as e:
                logger.warning(f"Error parsing HTML for URLs: {e}")
                # Fallback to regex for HTML if BS4 fails
                urls = URL_PATTERN.findall(html_content)
                for url in urls:
                    clean_url = url.rstrip(".,;:!?")
                    if clean_url not in links_map:
                        links_map[clean_url] = None

        # 2. Extract from Plain Text (Fallback / Supplemental)
        plain_text = self._extract_body_plain()
        if plain_text:
            text_urls = URL_PATTERN.findall(plain_text)
            for url in text_urls:
                clean_url = url.rstrip(".,;:!?")
                if clean_url not in links_map:
                    links_map[clean_url] = None

        return [Link(url=url, text=text) for url, text in links_map.items()]

    def _extract_attachments(self) -> List[Attachment]:
        """Extract attachment metadata with proper binary handling."""
        attachments = []

        if self.mail.attachments:
            for att in self.mail.attachments:
                try:
                    raw_payload = att.get("payload")
                    content_bytes = self._payload_to_bytes(raw_payload)

                    # Only keep first 2KB for magic number analysis
                    content_bytes = content_bytes[:2048] if content_bytes else None

                    attachment = Attachment(
                        filename=att.get("filename"), content_header=content_bytes
                    )
                    attachments.append(attachment)
                except Exception as e:
                    logger.warning(f"Failed to extract attachment: {e}")
                    continue

        return attachments

    def _payload_to_bytes(self, raw_payload) -> bytes:
        """
        Safely convert attachment payload to bytes.
        Handles: bytes, Base64 strings, and plain strings.
        """
        if raw_payload is None:
            return b""

        if isinstance(raw_payload, bytes):
            return raw_payload

        if isinstance(raw_payload, str):
            # Try Base64 decode first (common in MIME attachments)
            try:
                return base64.b64decode(raw_payload)
            except Exception as e:
                logger.warning(f"Failed to decode Base64 payload: {e}. Falling back to UTF-8.")
                # Fall back to UTF-8 encoding with error handling
                return raw_payload.encode("utf-8", errors="surrogateescape")

        return b""

    def _extract_auth_results(self) -> AuthHeaders:
        """
        Extract SPF, DKIM, and DMARC results using the authres library.
        """
        auth_header_raw = self.mail.headers.get("Authentication-Results")

        auth_header = ""
        if isinstance(auth_header_raw, list) and auth_header_raw:
            auth_header = str(auth_header_raw[0])
        elif isinstance(auth_header_raw, str):
            auth_header = auth_header_raw

        spf = None
        dkim = None
        dmarc = None

        if auth_header:
            try:
                parsed = authres.AuthenticationResultsHeader.parse(
                    f"Authentication-Results: {auth_header}"
                )
                for result in parsed.results:
                    method = result.method.lower()
                    status = result.result.lower() if result.result else None

                    if method == "spf" and spf is None:
                        spf = status
                    elif method == "dkim" and dkim is None:
                        dkim = status
                    elif method == "dmarc" and dmarc is None:
                        dmarc = status
            except Exception as e:
                logger.warning(f"Failed to parse Authentication-Results header: {e}")

        return AuthHeaders(spf=spf, dkim=dkim, dmarc=dmarc)

    def _extract_headers(self) -> Dict[str, str]:
        headers_dict = {}

        if self.mail.headers:
            for key, value in self.mail.headers.items():
                if isinstance(value, list):
                    headers_dict[key] = "; ".join(str(v) for v in value)
                else:
                    headers_dict[key] = str(value) if value else ""

        return headers_dict

    def _extract_header(self, key: str) -> Optional[str]:
        """Helper to extract a simple string header."""
        val = self.mail.headers.get(key)
        if isinstance(val, list) and val:
            return str(val[0])
        return str(val) if val else None
