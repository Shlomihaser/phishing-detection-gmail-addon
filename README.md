# Phishing Detection Gmail Add-on

![Python](https://img.shields.io/badge/Python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.128-green)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

An AI-powered phishing detection system that integrates with Gmail to analyze emails in real-time and warn users about potential threats.

## Features

- **Machine Learning Analysis**: Trained NLP model to detect phishing patterns in email content
- **Brand Protection**: Detects impersonation of major brands (Microsoft, PayPal, Google, etc.)
- **Link Analysis**: Identifies masked links, URL shorteners, suspicious TLDs, and raw IP usage
- **Attachment Scanning**: Detects dangerous file types, double extensions, and MIME spoofing
- **Authentication Verification**: Validates SPF, DKIM, and DMARC headers

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Gmail Inbox                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Google Apps Script                           │
│              (Gmail Add-on / Sidebar UI)                        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ HTTP POST (MIME Content)
┌─────────────────────────────────────────────────────────────────┐
│                     FastAPI Backend                             │
│  ┌───────────────┐  ┌────────────────┐  ┌──────────────────┐   │
│  │  Email Parser │──│ ML Classifier  │──│ Heuristic        │   │
│  │  (MIME→JSON)  │  │ (scikit-learn) │  │ Detectors        │   │
│  └───────────────┘  └────────────────┘  └──────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│                    ┌─────────────────┐                         │
│                    │ Scoring Service │                         │
│                    │ (Risk Analysis) │                         │
│                    └─────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼ JSON Response
┌─────────────────────────────────────────────────────────────────┐
│              Risk Assessment (Safe / Suspicious / Dangerous)    │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/phishing-detection-gmail-addon.git
cd phishing-detection-gmail-addon

# Build and run
docker-compose up --build

# API will be available at http://localhost:8000
```

### Local Development

```bash
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload

# API will be available at http://localhost:8000
```

## API Documentation

### Scan Email

**Endpoint:** `POST /api/scan`

**Request:**
```json
{
  "mime": "MIME-Version: 1.0\nFrom: sender@example.com\n..."
}
```

**Response:**
```json
{
  "status": "suspicious",
  "confidence": 65.5,
  "reasons": [
    "Sender claims to be 'Microsoft' but domain is not verified",
    "Link masking detected (text says 'google.com' but goes to 'evil.com')"
  ],
  "details": {
    "ml_score": 45.2,
    "ml_prediction": "phishing",
    "detectors": [
      {
        "name": "Brand Protection Detector",
        "impact": 75.0,
        "description": "Sender claims to be 'Microsoft' but domain is not verified"
      }
    ]
  }
}
```

### Status Levels

| Status | Score Range | Meaning |
|--------|-------------|---------|
| `safe` | 0-29 | No threats detected |
| `suspicious` | 30-69 | Potential risk, review recommended |
| `dangerous` | 70-100 | High risk, likely phishing |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Logging verbosity |

### Apps Script Setup

1. Open your Gmail Add-on project in [Google Apps Script](https://script.google.com)
2. Update the `API_URL` in `Config.gs`:
   ```javascript
   const CONFIG = {
     API_URL: "https://your-deployed-api.com/api/scan"
   };
   ```
3. Deploy and test

## Testing

```bash
# Run all tests
pytest backend/tests -v

# Run with coverage report
pytest backend/tests --cov=app --cov-report=term-missing

# Run specific test file
pytest backend/tests/unit/detectors/test_links.py -v
```

## Project Structure

```
phishing-detection-gmail-addon/
├── backend/
│   ├── app/
│   │   ├── api/              # API endpoints and dependencies
│   │   ├── constants/        # Configuration constants (brands, TLDs, etc.)
│   │   ├── detectors/        # Heuristic detection modules
│   │   ├── models/           # Pydantic models and ML artifacts
│   │   ├── services/         # Business logic (parser, scoring, ML)
│   │   └── main.py           # FastAPI application entry
│   ├── tests/
│   │   ├── unit/             # Unit tests for individual components
│   │   └── integration/      # API endpoint tests
│   ├── Dockerfile
│   └── requirements.txt
├── apps-script/              # Google Apps Script source
├── docker-compose.yml
└── README.md
```
