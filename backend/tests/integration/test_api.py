from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)


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
    assert data["details"]["ml_prediction"] == "SAFE"


def test_scan_endpoint_malformed_mime(mock_ml_service):
    """
    Scenario: Bad Input (User sending garbage).
    Goal: Send invalid non-MIME string -> Get 200 (Parser is resilient).
    """
    response = client.post("/api/scan", json={"mime": "NOT A MIME STRING"})
    assert response.status_code == 200


def test_scan_endpoint_crash_handling(mocker):
    """
    Scenario: Server Crash (500).
    Goal: Force a crash deeper in the stack -> Verify API catches it and returns 500 JSON.
    """
    mocker.patch(
        "app.detectors.links.MaliciousLinkDetector.evaluate",
        side_effect=Exception("Database Boom"),
    )

    from tests.factories import MockEmailBuilder

    raw_mime = MockEmailBuilder().build()

    response = client.post("/api/scan", json={"mime": raw_mime})
    assert response.status_code == 200  # Bulkhead pattern catches detector errors

    # To test 500, crash something outside the bulkhead
    mocker.patch(
        "app.services.email_parser.EmailParser.parse",
        side_effect=Exception("Critical Fail"),
    )

    response = client.post("/api/scan", json={"mime": raw_mime})

    assert response.status_code == 500
    assert "Internal server error" in response.json()["detail"]
