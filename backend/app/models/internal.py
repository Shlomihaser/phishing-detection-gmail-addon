from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

class AuthHeaders(BaseModel):
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None

class Email(BaseModel):
    message_id: str
    sender_name: Optional[str]
    sender_email: str
    reply_to: Optional[str]
    subject: str
    creation_date: datetime
    
    # extracted content
    body_text: str
    urls: List[str]
    email_addresses: List[str]
    
    # extracted headers
    auth_results: AuthHeaders
    headers: Dict[str, str]


