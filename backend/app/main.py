from fastapi import FastAPI
from app.api.routes import router as api_router
import uvicorn
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Phishing Detection API",
    description="Backend service for analyzing emails and detecting phishing attempts.",
    version="1.0.0"
)

app.include_router(api_router,prefix="/api")


if __name__ == "__main__":
    port = int(os.getenv("PORT",8000))
    uvicorn.run(app, host="0.0.0.0", port=port,reload=True)
