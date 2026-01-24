# Backend - Phishing Detection API

This service is the core backend for the Phishing Detection Gmail Add-on. It processes email content, runs heuristic detectors, and applies an ML model to determine the risk level of an email.

## 🛠️ Setup & Requirements

### 1. System Dependencies (Important)
This project uses `python-magic` for file type detection, which requires the underlying C-library `libmagic` to be installed on your operating system.

**For Windows Users:**
The easiest way is to install the binary package which includes the DLLs:
```bash
pip install python-magic-bin
```
*Note: If you are building via Docker (recommended), specific `libmagic1` packages are already included in the `Dockerfile`.*

**For macOS Users:**
You must install `libmagic` via Homebrew before installing Python requirements:
```bash
brew install libmagic
```

**For Linux Users:**
```bash
sudo apt-get install libmagic1
```

### 2. Install Python Dependencies
Once the system library is ready:
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

## 🚀 Running the App
To start the FastAPI server locally:
```bash
python -m app.main
```
The API will be available at: http://localhost:8000/docs

## 🐳 Running with Docker
The Docker build handles all dependencies (including `libmagic`) automatically.
```bash
docker build -t phishing-backend .
docker run -p 8000:8000 phishing-backend
```
