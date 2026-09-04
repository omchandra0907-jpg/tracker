"""
custom_routes.py
────────────────
FastAPI router for Live Intercept, Manual Input, and Drag-and-Drop File Uploads.
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from pydantic import BaseModel, Field

from extractor import ThreatExtractor
from correlator import CorrelationEngine

router = APIRouter(prefix="/api/v1/custom", tags=["Live Intercept"])
STORAGE_FILE = "user_posts.json"

_extractor = ThreatExtractor()

with open("osint_db.json", "r") as _f:
    _osint_data = json.load(_f)
_correlator = CorrelationEngine(_osint_data)


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


def _load_posts() -> list:
    if not os.path.exists(STORAGE_FILE):
        return []
    try:
        with open(STORAGE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_post(author: str, content: str, timestamp: str) -> None:
    posts = _load_posts()
    posts.insert(0, {"author": author, "content": content, "timestamp": timestamp})
    with open(STORAGE_FILE, "w") as f:
        json.dump(posts, f, indent=2)


def _analyze(author: str, content: str, timestamp: Optional[str] = None) -> dict:
    iocs = _extractor.extract(content)
    suspects = _correlator.calculate_risk(iocs, content)
    return {
        "darkweb_alias": author,
        "extracted_indicators": iocs,
        "deanonymization_results": suspects,
        "is_custom": True,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
    }


@router.post("/analyze")
def submit_and_analyze(req: PostSubmissionRequest):
    author = (req.author or "UNKNOWN_ACTOR").strip() or "UNKNOWN_ACTOR"
    timestamp = datetime.now(timezone.utc).isoformat()
    report = _analyze(author, req.content, timestamp)
    _save_post(author, req.content, timestamp)
    return {"status": "success", "result": report}


@router.get("/feed")
def get_custom_feed():
    raw_posts = _load_posts()
    results = [
        _analyze(p["author"], p["content"], p.get("timestamp"))
        for p in raw_posts
    ]
    return {"status": "success", "count": len(results), "results": results}


@router.delete("/feed")
def clear_custom_feed():
    if os.path.exists(STORAGE_FILE):
        os.remove(STORAGE_FILE)
    return {"status": "success", "message": "Custom intercept feed cleared."}


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    author: Optional[str] = Form(None),
):
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

    content = raw_bytes.decode("utf-8", errors="ignore").strip()
    if len(content) < 5:
        raise HTTPException(status_code=400, detail="File contains too little readable text (< 5 chars).")

    stem = os.path.splitext(file.filename or "UNKNOWN")[0]
    author_alias = (author or stem or "UNKNOWN_ACTOR").strip() or "UNKNOWN_ACTOR"
    timestamp = datetime.now(timezone.utc).isoformat()

    report = _analyze(author_alias, content, timestamp)
    _save_post(author_alias, content, timestamp)
    return {"status": "success", "result": report}
