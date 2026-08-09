import datetime
import os
from typing import List, Dict, Optional
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from analyzer.rules import analyze_text_rules
from analyzer.url_analyzer import analyze_urls_in_text
from analyzer.risk_engine import calculate_risk
from rag.retriever import retrieve_context
from rag.explainer import generate_explanation
from llm.explanation import get_explanation_from_llm

app = FastAPI(
    title="Scam Shield API",
    description="Pre-click scam detection API for suspicious WhatsApp/SMS messages.",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permissive for hackathon development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Error Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Handle validation errors such as missing/empty text or invalid field types.
    Returns HTTP 400.
    """
    # Check if it's a value error from our validator or missing text field
    errors = exc.errors()
    error_msg = "Invalid request format."
    
    for err in errors:
        loc = err.get("loc", [])
        if "text" in loc:
            error_msg = "Message text is required."
            break
            
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": error_msg}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Handle HTTP exceptions.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Fallback error handler to prevent stack traces from leaking to API clients.
    """
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "An unexpected internal error occurred."}
    )


# Pydantic Request Models
class CheckRequest(BaseModel):
    text: str = Field(..., description="Message text to analyze")

    @field_validator('text')
    @classmethod
    def text_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Message text is required.')
        return v

class ReportRequest(BaseModel):
    text: str = Field(..., description="Scam message text to report")
    notes: Optional[str] = Field(None, description="Optional extra notes")

    @field_validator('text')
    @classmethod
    def text_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Message text is required.')
        return v


# In-memory storage for scam reports
# Pre-seeded with 3 mock entries
REPORTS_DB: List[Dict] = [
    {
        "text": "e-Challan.apk with fake parivahaan.com link",
        "notes": "Pre-seeded report",
        "timestamp": "2026-08-09T10:30:00Z"
    },
    {
        "text": "MParivahan.apk from spoofed WhatsApp Business account",
        "notes": "Pre-seeded report",
        "timestamp": "2026-08-09T10:15:00Z"
    },
    {
        "text": "RTO_Challan.apk sent via WhatsApp claiming vehicle fine",
        "notes": "Pre-seeded report",
        "timestamp": "2026-08-09T10:00:00Z"
    }
]


# API Endpoints
@app.get("/api/health")
def health_check():
    """
    Simple API health status check.
    """
    return {
        "status": "ok",
        "service": "Scam Shield API"
    }

@app.post("/api/check")
def check_message(payload: CheckRequest):
    """
    Executes the complete pre-click scam analysis pipeline.
    """
    text = payload.text
    
    # 1. Analyze rules-based keywords (category, APK, urgency)
    rules_res = analyze_text_rules(text)
    
    # 2. Extract and analyze URLs
    urls_res = analyze_urls_in_text(text)
    
    # Determine the category:
    # If suspicious indicators exist but no category matches, default to General Scam / Phishing.
    strongest_cat = rules_res["strongest_category"]
    has_indicators = (
        rules_res["apk_detected"] or 
        rules_res["urgency_detected"] or 
        urls_res["found_suspicious"]
    )
    
    if not strongest_cat:
        if has_indicators:
            category = "General Scam / Phishing"
        else:
            category = "None"
    else:
        category = strongest_cat
        
    # 3. Calculate risk score & verdict
    score, verdict, confidence, indicators, base_reasons, action = calculate_risk(
        category=category,
        rules_analysis=rules_res,
        url_analysis=urls_res
    )
    
    # 4. RAG context retrieval
    rag_res = retrieve_context(
        message=text,
        detected_category=category,
        indicators=indicators
    )
    
    # 5. Explainer block (Fallback generation)
    reasons = generate_explanation(
        message=text,
        rules_analysis=rules_res,
        url_analysis=urls_res,
        rag_context=rag_res["context"]
    )
    
    # If no reasons were generated (e.g. completely clean message), default to safe explanation
    if not reasons and verdict == "safe":
        reasons = ["The message does not contain any suspicious keywords, files, or link patterns."]
        
    # 6. Structured LLM / Fallback Explanation Layer
    explanation, explanation_source = get_explanation_from_llm(
        message=text,
        category=category,
        verdict=verdict,
        score=score,
        confidence=confidence,
        indicators=indicators,
        reasons=reasons,
        url_analysis=urls_res,
        rag_context=rag_res["context"]
    )
        
    return {
        "verdict": verdict,
        "score": score,
        "category": category,
        "confidence": confidence,
        "indicators": indicators,
        "reasons": reasons,
        "url_analysis": {
            "found": urls_res["found"],
            "urls": [
                {
                    "url": u["url"],
                    "domain": u["domain"],
                    "status": u["status"],
                    "reason": u["reason"]
                }
                for u in urls_res["urls"]
            ]
        },
        "rag_context": rag_res["context"],
        "explanation": explanation,
        "explanation_source": explanation_source,
        "action": action
    }

@app.post("/api/report")
def report_scam(payload: ReportRequest):
    """
    Submits a new scam report which is stored in memory.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    
    new_report = {
        "text": payload.text,
        "notes": payload.notes,
        "timestamp": timestamp
    }
    
    # Insert at the beginning of the list to keep it newest-first
    REPORTS_DB.insert(0, new_report)
    
    return {
        "status": "reported"
    }

@app.get("/api/reports")
def get_reports():
    """
    Returns the newest scam reports (up to 20 entries).
    """
    # The REPORTS_DB is maintained as newest-first, slice to max 20 entries
    return REPORTS_DB[:20]
