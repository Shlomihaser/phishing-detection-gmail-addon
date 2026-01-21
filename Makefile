VENV = backend/venv
PYTHON = $(VENV)/Scripts/python
PIP = $(VENV)/Scripts/pip

run:
	@echo "Starting FastAPI Server..."
	export PYTHONPATH=backend && $(PYTHON) -m app.main

install:
	$(PIP) install -r backend/requirements.txt

tunnel:
	@echo "--- Starting ngrok Tunnel on port 8000 ---"
	ngrok http 8000