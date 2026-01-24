from typing import List, Dict, Optional
from pydantic import BaseModel

class Link(BaseModel):
    url: str
    text: Optional[str] = None

class AuthHeaders(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None

class Attachment(BaseModel):
    filename: Optional[str]
    content_header: Optional[bytes] = None

class Email(BaseModel):
    sender_name: Optional[str]
    sender_email: str
    reply_to: Optional[str]
    subject: Optional[str] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    urls: List[Link]
    attachments: List[Attachment] = []
    auth_results: AuthHeaders
    headers: Dict[str, str]
    return_path: Optional[str] = None
    x_mailer: Optional[str] = None
    message_id: Optional[str] = None



