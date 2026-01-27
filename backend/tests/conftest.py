import pytest
import logging
from unittest.mock import MagicMock
from tests.factories import MockEmailBuilder

# Disable logging noise during tests
logging.getLogger("faker").setLevel(logging.ERROR)


@pytest.fixture
def email_builder():
    """
    Fixture that returns a fresh instance of MockEmailBuilder for each test.
    """
    return MockEmailBuilder()



