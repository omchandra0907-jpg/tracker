"""
custom_routes.py
────────────────
Isolated FastAPI router for the "Live Intercept / User-Input" feature.

Mounting in main.py (one-time, already done):
    from custom_routes import router as custom_router
    app.include_router(custom_router)

All endpoints live under /api/v1/custom — zero collision with existing routes.
User posts are persisted in user_posts.json (added to .gitignore).
This file is fully self-contained; no changes to main.py are ever needed again.
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel, Field

from extractor import ThreatExtractor
from correlator import CorrelationEngine

# ── Router ────────────────────────────────────────────────────────
router = APIRouter(prefix="/api/v1/custom", tags=["Live Intercept"])

STORAGE_FILE = "user_posts.json"

# Own instances — independent of main.py so teammates can refactor
# main.py's extractor/correlator without breaking this module.
_extractor = ThreatExtractor()

with open("osint_db.json", "r") as _f:
    _osint_data = json.load(_f)
_correlator = CorrelationEngine(_osint_data)


# ── Request schema ────────────────────────────────────────────────
class PostSubmissionRequest(BaseModel):
    author: Optional[str] = Field(
        default="UNKNOWN_ACTOR",
        max_length=64,
        description="Forum alias or handle (optional)",
    )
    content: str = Field(
        ...,
        min_length=5,
        description="Raw intercepted text — forum post, chat log, ransom note, etc.",
    )


# ── Persistence helpers ───────────────────────────────────────────
def _load_posts() -> list:
    """Read persisted user-submitted posts from disk."""
    if not os.path.exists(STORAGE_FILE):
        return []
    try:
        with open(STORAGE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_post(author: str, content: str, timestamp: str) -> None:
    """Prepend a new post to the storage file so newest is always first."""
    posts = _load_posts()
    posts.insert(0, {"author": author, "content": content, "timestamp": timestamp})
    with open(STORAGE_FILE, "w") as f:
        json.dump(posts, f, indent=2)


# ── Core analysis helper ──────────────────────────────────────────
def _analyze(author: str, content: str, timestamp: Optional[str] = None) -> dict:
    """
    Run the full IOC extraction + correlation pipeline on a single text block.

    Returns a dict in the exact same schema as /api/v1/analyze results so the
    existing frontend renderList() and renderGraph() functions work unchanged.
    The extra 'is_custom' flag is used only by the frontend to show the
    LIVE INTERCEPT badge — it is ignored by the graph renderer.
    """
    iocs = _extractor.extract(content)
    suspects = _correlator.calculate_risk(iocs, content)
    return {
        "darkweb_alias": author,
        "extracted_indicators": iocs,
        "deanonymization_results": suspects,
        "is_custom": True,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
    }


# ── Endpoints ─────────────────────────────────────────────────────

@router.post("/analyze")
def submit_and_analyze(req: PostSubmissionRequest):
    """
    Analyze a user-submitted dark web post in real time and persist it locally.

    Response schema is compatible with /api/v1/analyze so the frontend
    can render it without any changes to the graph or card logic.
    """
    author = (req.author or "UNKNOWN_ACTOR").strip() or "UNKNOWN_ACTOR"
    timestamp = datetime.now(timezone.utc).isoformat()

    report = _analyze(author, req.content, timestamp)
    _save_post(author, req.content, timestamp)

    return {"status": "success", "result": report}


@router.get("/feed")
def get_custom_feed():
    """
    Return all previously submitted user posts, re-analyzed against the current
    OSINT database. Called on page load so intercepts survive page refreshes.
    """
    raw_posts = _load_posts()
    results = [
        _analyze(p["author"], p["content"], p.get("timestamp"))
        for p in raw_posts
    ]
    return {"status": "success", "count": len(results), "results": results}


@router.delete("/feed")
def clear_custom_feed():
    """Remove all user-submitted posts. Useful for resetting between demo sessions."""
    if os.path.exists(STORAGE_FILE):
        os.remove(STORAGE_FILE)
    return {"status": "success", "message": "Custom intercept feed cleared."}


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    author: Optional[str] = Form(None),
):
    """
    Accept a raw file upload (.txt, .log, .json, .eml, .csv) and run the same
    de-anonymization pipeline as /analyze.

    The pipeline is identical to POST /analyze — only the text ingestion method
    differs (file bytes → utf-8 decode instead of JSON body field).

    Used by the browser's drag-and-drop zone via a multipart/form-data POST.
    Can also be called directly via curl:
        curl -F "file=@leak.log" -F "author=hydra99" http://localhost:8000/api/v1/custom/upload
    """
    ALLOWED_EXTENSIONS = {".txt", ".log", ".json", ".eml", ".csv", ".md"}
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Decode tolerantly — ignore unrecognised bytes (e.g. Windows-1252 artifacts)
    content = raw_bytes.decode("utf-8", errors="ignore").strip()

    if len(content) < 5:
        raise HTTPException(status_code=400, detail="File contains too little readable text (< 5 chars).")

    # Default alias to filename stem if not provided
    stem = os.path.splitext(file.filename or "UNKNOWN")[0]
    author_alias = (author or stem or "UNKNOWN_ACTOR").strip() or "UNKNOWN_ACTOR"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Delegate to the same shared helpers — identical pipeline as /analyze
    report = _analyze(author_alias, content, timestamp)
    _save_post(author_alias, content, timestamp)

    return {"status": "success", "result": report}
