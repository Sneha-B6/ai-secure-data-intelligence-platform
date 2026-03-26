import logging
import time
from fastapi import FastAPI, Request
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from app.routes.analyze import router as analyze_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    version="2.0.0",
    description="AI-powered platform for detecting sensitive data, analyzing security risks, and enforcing data policies"
)

# CORS configuration
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://ai-secure-data-intelligence-platfor-azure.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = round((time.time() - start) * 1000, 1)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} ({duration}ms)")
    return response


# Routes
app.include_router(analyze_router)


@app.get("/", tags=["Health"])
def root():
    return {
        "message": "AI Secure Data Intelligence Platform running",
        "version": "2.0.0",
        "endpoints": ["/api/analyze", "/api/analyze-file", "/health"]
    }


@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "services": {
            "parser": "active",
            "detector": "active",
            "log_analyzer": "active",
            "risk_engine": "active",
            "policy_engine": "active",
            "ai_service": "active"
        }
    }
