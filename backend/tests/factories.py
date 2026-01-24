import logging
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Optional, Dict

class MockEmailBuilder:
    """
    Builder pattern for creating raw MIME email strings for testing.
    Avoids manual string concatenation of complex MIME formats.
    """
    
    def __init__(self):
        self.msg = MIMEMultipart()
        # Default safe values
        self.msg['From'] = "alice@example.com"
        self.msg['To'] = "bob@example.com"
        self.msg['Subject'] = "Test Email"
        self.body_plain = "This is a test email."
        self.body_html = None
    
    def with_sender(self, sender: str):
        del self.msg['From']
        self.msg['From'] = sender
        return self
    
    def with_subject(self, subject: str):
        del self.msg['Subject']
        self.msg['Subject'] = subject
        return self
        
    def with_body(self, plain: str, html: Optional[str] = None):
        self.body_plain = plain
        self.body_html = html
        return self

    def with_header(self, key: str, value: str):
        self.msg[key] = value
        return self

    def with_attachment(self, filename: str, content: bytes, content_type: str = "application/octet-stream"):
        """Add an attachment to the email."""
        part = MIMEApplication(content)
        part.add_header('Content-Disposition', 'attachment', filename=filename)
        # Manually set content-type if needed
        if content_type:
            part.set_param('name', filename) # fallback
            # We generally let MIMEApplication handle defaults or overwrite if tricky
        self.msg.attach(part)
        return self

    def build(self) -> str:
        """Finalize and return raw MIME string."""
        # Attach bodies
        if self.body_html:
            self.msg.attach(MIMEText(self.body_plain, 'plain'))
            self.msg.attach(MIMEText(self.body_html, 'html'))
        else:
            self.msg.attach(MIMEText(self.body_plain, 'plain'))
            
        return self.msg.as_string()
