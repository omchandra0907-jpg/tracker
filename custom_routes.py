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

from fastapi import APIRouter
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
