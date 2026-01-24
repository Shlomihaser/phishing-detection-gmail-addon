# Phishing Detection Gmail Add-on

![Python](https://img.shields.io/badge/Python-3.13-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.128-green)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

A Gmail add-on that scans incoming emails for phishing attempts. Uses a combination of ML text classification and rule-based heuristics to catch the stuff that slips past spam filters.

## What It Checks

- **Text content**: ML model trained on phishing datasets to catch suspicious language
- **Sender identity**: Flags emails claiming to be from Microsoft, PayPal, etc. but sent from unrelated domains
- **Links**: Catches masked URLs, shorteners, raw IPs, and sketchy TLDs
- **Attachments**: Detects dangerous extensions, double-extension tricks (invoice.pdf.exe), and files pretending to be something they're not
- **Email auth**: Verifies SPF/DKIM/DMARC headers

## Detection Logic

The final risk score is calculated using a weighted combination:

| Component | Weight | Description |
|-----------|--------|-------------|
| Heuristic Detectors | 60% | Rule-based checks (see table below) |
| ML Model | 40% | Text classification confidence |

### Detector Scoring Matrix

| Detector | Trigger | Risk Impact |
|----------|---------|-------------|
| **Dangerous Attachment** | `.exe`, `.scr`, `.bat`, etc. | 100 (Critical) |
| **Hidden Executable** | File claims to be `.pdf` but is actually `.exe` | 100 (Critical) |
| **Double Extension** | `invoice.pdf.exe` | 100 (Critical) |
| **Brand Impersonation** | Name says "Microsoft", domain is `random@gmail.com` | 75 (High) |
| **MIME Mismatch** | Extension doesn't match file content | 75 (High) |
| **Domain Typosquatting** | `micr0soft.com`, `paypa1.com` | 60 (Medium) |
| **Link Masking** | Text shows `google.com`, href goes to `evil.com` | 50 (Medium) |
| **Raw IP in URL** | `http://192.168.1.1/login` | 40 (Medium) |
| **Auth Failure** | SPF/DKIM/DMARC failed | 40-100 |
| **URL Shortener** | `bit.ly`, `tinyurl.com` | 25 (Low) |
| **Suspicious TLD** | `.xyz`, `.top`, `.buzz` | 20 (Low) |

### ML Model

- **Algorithm**: Multinomial Naive Bayes (scikit-learn)
- **Features**: TF-IDF vectorized email text (subject + body), max 5000 features, unigrams + bigrams
- **Dataset**: [Kaggle Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) (CEAS 2008 corpus)
- **Split**: 80/20 train/test with `random_state=42`

**Why only subject + body?** The dataset includes additional columns, but we intentionally use only text content. This lets the model focus on detecting linguistic patterns common in phishing:
- Urgent language ("Act now!", "Your account will be suspended")
- Authority impersonation ("Dear valued customer", "Security team")
- Reward/threat framing ("You've won!", "Verify immediately or lose access")


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

### Gmail Add-on Setup

1. **Create a new Apps Script project**
   - Go to [script.google.com](https://script.google.com)
   - Click **New project**
   - Rename it to "Phishing Detector"

2. **Copy the add-on files**
   - Create the following files in your project and copy the contents from `gmail-addon/`:
     - `Config.gs`
     - `Main.gs`
     - `UI.gs`
   - Rename `appsscript.json`: Click the gear icon → **Project Settings** → Check "Show 'appsscript.json' manifest file"
   - Replace the content of `appsscript.json` with the one from `gmail-addon/appsscripts.json`

3. **Configure the API URL**
   - In Apps Script Editor, go to **Project Settings** (gear icon)
   - Scroll to **Script Properties**
   - Click **Add script property**
   - Set: `API_URL` = `https://your-api-domain.com/api/scan`
   
   Or run this once in the editor:
   ```javascript
   setApiUrl("https://your-api-domain.com/api/scan")
   ```

4. **Deploy as a test add-on**
   - Click **Deploy** → **Test deployments**
   - Under **Gmail**, click **Install**
   - Open Gmail and look for the add-on icon in the right sidebar when viewing an email

> **Note**: For local testing, use a tunneling service like [ngrok](https://ngrok.com) to expose your local API:
> ```bash
> ngrok http 8000
> # Then set API_URL to: https://abc123.ngrok.io/api/scan
> ```

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
├── gmail-addon/              # Google Apps Script source
├── docker-compose.yml
└── README.md
```
