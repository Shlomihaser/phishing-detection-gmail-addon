import pytest
import logging
from unittest.mock import MagicMock
from .factories import MockEmailBuilder

# Disable logging noise during tests
logging.getLogger("faker").setLevel(logging.ERROR)

@pytest.fixture
def email_builder():
    """
    Fixture that returns a fresh instance of MockEmailBuilder for each test.
    Usage:
        def test_something(email_builder):
            mime = email_builder.with_sender("evul").build()
    """
    return MockEmailBuilder()

from app.main import app
from app.api.dependencies import get_ml_service

@pytest.fixture
def mock_ml_service():
    """
    Mocks the MLService using FastAPI dependency overrides.
    This ensures the app uses our mock instead of the real heavy service.
    """
    mock_instance = MagicMock()
    mock_instance.predict.return_value = {
        "is_phishing": False,
        "confidence": 0.1
    }
    
    # Override the dependency
    app.dependency_overrides[get_ml_service] = lambda: mock_instance
    
    yield mock_instance
    
    # Clean up
    app.dependency_overrides = {}
