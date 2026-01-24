class PhishingAppError(Exception):
    """Base exception for the application."""

    pass


class EmailParsingError(PhishingAppError):
    """Raised when the email content cannot be parsed."""

    pass
