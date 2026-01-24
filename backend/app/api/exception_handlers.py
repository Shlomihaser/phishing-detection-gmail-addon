from fastapi import Request, status
from fastapi.responses import JSONResponse
import logging

from app.exceptions import EmailParsingError

logger = logging.getLogger(__name__)


async def email_parsing_exception_handler(request: Request, exc: EmailParsingError):
    logger.warning(f"Email parsing error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": f"Invalid email content: {str(exc)}"},
    )


async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error executing scan."},
    )
