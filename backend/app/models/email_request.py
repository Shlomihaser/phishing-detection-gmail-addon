from pydantic import BaseModel, Field

class EmailRequest(BaseModel):
    """Schema representing the expanded email data sent from the Gmail Add-on."""
    mime: str = Field(..., description="The raw MIME content of the email")

    