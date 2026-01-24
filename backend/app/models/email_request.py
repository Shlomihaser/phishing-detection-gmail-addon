from pydantic import BaseModel, Field

MAX_MIME_SIZE = 25 * 1024 * 1024  # Gmail's maximum email size is 25MB in bytes

class EmailRequest(BaseModel):
    mime: str = Field(..., description="The raw MIME content of the email",max_length=MAX_MIME_SIZE)

    