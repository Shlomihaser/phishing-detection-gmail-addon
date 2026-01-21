from pydantic import BaseModel, Field

class EmailRequest(BaseModel):
    """Schema representing the expanded email data sent from the Gmail Add-on."""
    
    messageId: str = Field(..., description="Unique Gmail message ID")
    subject: str = Field(..., description="The subject line of the email")
    body: str = Field(..., description="The plain text content of the email body")
    sender: str = Field(..., description="The sender's name and email address")
    date: str = Field(..., description="The ISO timestamp of the email")
    threadId: str = Field(..., description="The Gmail thread ID for context analysis")
    rawContent: str = Field(..., description="The full RFC822 raw content for deep parsing")

    class Config:
        json_schema_extra = {
            "example": {
                "messageId": "msg-123",
                "subject": "Urgent: Reset your password",
                "body": "Click here to reset your password...",
                "sender": "Security <security@fake-bank.com>",
                "date": "2023-10-27T10:00:00Z",
                "threadId": "thread-456",
                "rawContent": "From: security@fake-bank.com\nTo: user@gmail.com..."
            }
        }
