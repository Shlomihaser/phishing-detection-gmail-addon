from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_scan_endpoint_success(email_builder, mock_ml_service):
    """
    Scenario: Happy Path Scan.
    Goal: Send a valid email MIME -> Get back a 200 JSON response with risk analysis.
    """
    raw_mime = (
        email_builder.with_sender("user@example.com").with_subject("Safe Email").build()
    )

    response = client.post("/api/scan", json={"mime": raw_mime})

    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "confidence" in data
    assert data["details"]["ml_prediction"] == "safe"


def test_scan_endpoint_malformed_mime(mock_ml_service):
    """
    Scenario: Bad Input (User sending garbage).
    Goal: Send invalid non-MIME string -> Get 200 (Parser is resilient).
    """
    response = client.post("/api/scan", json={"mime": "NOT A MIME STRING"})

    # Python's email parser is VERY distinct: it swallows almost anything.
    # So this test serves as a "Smoke Test" that the API doesn't crash even on garbage.
    assert response.status_code == 200


def test_scan_endpoint_crash_handling(mocker):
    """
    Scenario: Server Crash (500).
    Goal: Force a crash deeper in the stack -> Verify API catches it and returns 500 JSON.
    """
    # Force ScoringService to explode (Caught by Bulkhead)
    mocker.patch(
        "app.detectors.links.MaliciousLinkDetector.evaluate",
        side_effect=Exception("Database Boom"),
    )

    # We need a builder to get past the parsing stage
    from tests.factories import MockEmailBuilder

    raw_mime = MockEmailBuilder().build()

    response = client.post("/api/scan", json={"mime": raw_mime})

    # Bulkhead pattern catches detector errors!
    assert response.status_code == 200

    # To test actual 500, we must crash something OUTSIDE the bulkhead.
    mocker.patch(
        "app.services.email_parser.EmailParser.parse",
        side_effect=Exception("Critical Fail"),
    )

    # Note: TestClient raises the exception directly in the test process for 500s 
    # unless we configure it otherwise, but our Exception Handler catches it 
    # and returns a JSONResponse, so response.status_code should be 500.
    response = client.post("/api/scan", json={"mime": raw_mime})

    assert response.status_code == 500
    assert "Internal server error" in response.json()["detail"]
