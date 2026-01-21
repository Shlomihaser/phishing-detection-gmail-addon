import uvicorn

from app.settings.config import settings
from fastapi import FastAPI
from app.api.endpoints.scan import router as api_router


app = FastAPI(
    title="Phishing Detection API",
    description="Backend service for analyzing emails and detecting phishing attempts.",
    version="1.0.0"
)

app.include_router(api_router,prefix="/api")

if __name__ == "__main__":
    port = settings.PORT
    uvicorn.run("app.main:app", host="0.0.0.0", port=port,reload=True)
