import uvicorn
import app.detectors  

from fastapi import FastAPI

from app.settings.config import settings
from app.api.endpoints.scan import router as api_router
from app.exceptions import EmailParsingError
from app.api.exception_handlers import (
    email_parsing_exception_handler,
    general_exception_handler,
)

app = FastAPI(
    title="Phishing Detection API",
    description="Backend service for analyzing emails and detecting phishing attempts.",
    version="1.0.0",
)

app.add_exception_handler(EmailParsingError, email_parsing_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)

app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    port = settings.PORT
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
