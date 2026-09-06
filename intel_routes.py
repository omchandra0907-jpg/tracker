"""
Analytical front-end support: timeline querying, CSV/JSON/report export,
and two capability stubs (infrastructure misconfiguration correlation +
persona/stylometric linkage) that are seeded with curated demo data for
now... The response shapes here are the intended production contract
swapping the seeded lookups for a live Tor-probing service and a real
stylometry model later should not require changing this API surface. <3
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse, PlainTextResponse

from extractor import ThreatExtractor
from correlator import CorrelationEngine
from custom_routes import _load_posts 

router = APIRouter(prefix="/api/v1", tags=["Timeline & Export & Advanced Correlation"])

_extractor = ThreatExtractor()

with open("osint_db.json", "r") as _f:
    _osint_data = json.load(_f)
_correlator = CorrelationEngine(_osint_data)

_actor_lookup = {a["real_name"]: a for a in _osint_data}
_onion_to_actor = {
    onion.lower(): a["real_name"]
    for a in _osint_data
    for onion in a.get("known_onions", [])
}


# shared helpers

def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid date/time: '{value}'. Use ISO-8601, e.g. 2026-08-01.")


def _analyze_post(author: str, content: str, timestamp: Optional[str], is_custom: bool) -> dict:
    iocs = _extractor.extract(content)
    suspects = _correlator.calculate_risk(
        iocs,
        content,
        post_author=author,
        timestamp=timestamp,
    )
    return {
        "darkweb_alias": author,
        "extracted_indicators": iocs,
        "deanonymization_results": suspects,
        "timestamp": timestamp,
        "is_custom": is_custom,
    }


def _build_dataset(source: str = "all") -> list:
    """Re-runs extraction/correlation over the mock feed and/or the live
    intercept feed, tagging each result with its origin and timestamp so it
    can be filtered by a timeline range or exported."""
    results = []

    if source in ("all", "feed"):
        with open("mock_feed.json", "r") as f:
            mock_posts = json.load(f)
        for post in mock_posts:
            results.append(_analyze_post(post["author"], post["content"], post.get("timestamp"), False))

    if source in ("all", "custom"):
        for post in _load_posts():
            results.append(_analyze_post(post["author"], post["content"], post.get("timestamp"), True))

    return results


def _filter_by_timeline(dataset: list, start: Optional[datetime], end: Optional[datetime]) -> list:
    if not start and not end:
        return dataset

    filtered = []
    for item in dataset:
        ts = _parse_dt(item.get("timestamp")) if item.get("timestamp") else None
        if ts is None:
            continue  
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        filtered.append(item)
    return filtered


def _flatten_rows(dataset: list) -> list:
    """One row per (post, matched suspect) pair — the natural export grain."""
    rows = []
    for item in dataset:
        matches = item.get("deanonymization_results") or []
        if not matches:
            rows.append({
                "timestamp": item.get("timestamp") or "",
                "darkweb_alias": item.get("darkweb_alias", ""),
                "source": "live_intercept" if item.get("is_custom") else "mock_feed",
                "suspect_name": "",
                "surface_platform": "",
                "category": "",
                "last_scan_date": "",
                "confidence_score": "",
                "evidence": "",
            })
            continue
        for s in matches:
            profile = _actor_lookup.get(s["suspect_name"], {})
            rows.append({
                "timestamp": item.get("timestamp") or "",
                "darkweb_alias": item.get("darkweb_alias", ""),
                "source": "live_intercept" if item.get("is_custom") else "mock_feed",
                "suspect_name": s.get("suspect_name", ""),
                "surface_platform": s.get("surface_platform", ""),
                "category": profile.get("category", ""),
                "last_scan_date": profile.get("last_scan_date", ""),
                "confidence_score": s.get("confidence_score", ""),
                "evidence": "; ".join(s.get("evidence", [])),
            })
    return rows


# Timeline query

@router.get("/timeline")
def query_timeline(
    start: Optional[str] = Query(None, description="ISO date/time, e.g. 2026-08-01"),
    end: Optional[str] = Query(None, description="ISO date/time, e.g. 2026-09-01"),
    source: str = Query("all", pattern="^(all|feed|custom)$"),
):
    """Query correlated threat-actor intelligence across a chosen timeline."""
    start_dt = _parse_dt(start)
    end_dt = _parse_dt(end)
    dataset = _build_dataset(source)
    filtered = _filter_by_timeline(dataset, start_dt, end_dt)
    filtered.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

    return {
        "status": "success",
        "range": {"start": start, "end": end},
        "source": source,
        "count": len(filtered),
        "results": filtered,
    }


# Export (CSV / JSON / report)

@router.get("/export/{fmt}")
def export_results(
    fmt: str,
    start: Optional[str] = Query(None),
    end: Optional[str] = Query(None),
    source: str = Query("all", pattern="^(all|feed|custom)$"),
):
    if fmt not in ("csv", "json", "report"):
        raise HTTPException(status_code=400, detail="format must be one of: csv, json, report")

    start_dt = _parse_dt(start)
    end_dt = _parse_dt(end)
    dataset = _filter_by_timeline(_build_dataset(source), start_dt, end_dt)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if fmt == "json":
        payload = json.dumps({"exported_at": stamp, "range": {"start": start, "end": end}, "results": dataset}, indent=2)
        return StreamingResponse(
            io.StringIO(payload),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="threat_intel_export_{stamp}.json"'},
        )

    rows = _flatten_rows(dataset)

    if fmt == "csv":
        buf = io.StringIO()
        fieldnames = ["timestamp", "darkweb_alias", "source", "suspect_name",
                      "surface_platform", "category", "last_scan_date", "confidence_score", "evidence"]
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="threat_intel_export_{stamp}.csv"'},
        )


    lines = [
        "DARK WEB THREAT ACTOR DE-ANONYMIZATION — INTELLIGENCE REPORT",
        f"Generated: {stamp}",
        f"Timeline: {start or 'earliest'} → {end or 'latest'}   Source: {source}",
        f"Records analyzed: {len(dataset)}",
        "=" * 72,
    ]
    for row in sorted(rows, key=lambda r: (r["confidence_score"] if isinstance(r["confidence_score"], int) else -1), reverse=True):
        if not row["suspect_name"]:
            continue
        lines.append(
            f"[{row['confidence_score']}%] {row['suspect_name']} ({row['category'] or 'Uncategorized'})\n"
            f"    Surface alias post : {row['darkweb_alias']}  |  Source: {row['source']}  |  Timestamp: {row['timestamp']}\n"
            f"    Platform           : {row['surface_platform']}\n"
            f"    Last scan          : {row['last_scan_date']}\n"
            f"    Evidence           : {row['evidence']}\n"
        )
    report_text = "\n".join(lines)
    return PlainTextResponse(
        report_text,
        headers={"Content-Disposition": f'attachment; filename="threat_intel_report_{stamp}.txt"'},
    )


# Infrastructure misconfiguration correlation (seeded placeholder)

_INFRA_SEED = {
    "lockbitapt6vx57t3eeqjofwgcglmutr3a35nyzyvhdp3qq4weewrvqd.onion": {
        "exposed_server_status": True,
        "ssl_certificate_reused_on_clearnet": {"found": True, "clearnet_domain": "demo-mirror.example-hosting.net", "common_name": "demo-mirror.example-hosting.net"},
        "default_service_banner": "nginx/1.18.0 (Ubuntu)",
        "descriptor_inconsistency": True,
        "likely_clearnet_origin": {"ip": "203.0.113.42", "asn": "AS64500 (DEMO-HOSTING)", "hosting_provider": "Example Bulletproof Hosting Ltd. (synthetic)"},
        "confidence": 78,
    },
    "contileaks7j27464y6g26.onion": {
        "exposed_server_status": False,
        "ssl_certificate_reused_on_clearnet": {"found": True, "clearnet_domain": "leak-mirror.example-cdn.net", "common_name": "*.example-cdn.net"},
        "default_service_banner": None,
        "descriptor_inconsistency": False,
        "likely_clearnet_origin": {"ip": "198.51.100.17", "asn": "AS64501 (DEMO-CDN)", "hosting_provider": "Example CDN Networks (synthetic)"},
        "confidence": 52,
    },
    "bulletproofvpngy27464y6g26.onion": {
        "exposed_server_status": True,
        "ssl_certificate_reused_on_clearnet": {"found": False, "clearnet_domain": None, "common_name": None},
        "default_service_banner": "Apache/2.4.41 (Debian) — default landing page",
        "descriptor_inconsistency": True,
        "likely_clearnet_origin": {"ip": None, "asn": None, "hosting_provider": None},
        "confidence": 34,
    },
}


@router.get("/infra/scan")
def infra_scan(onion: str = Query(..., description="Onion address to check for misconfiguration indicators")):
    clean = onion.lower().strip().replace("http://", "").replace("https://", "").strip("/")
    matched_actor = _onion_to_actor.get(clean)  # this part is a real lookup against the actor graph
    seed = _INFRA_SEED.get(clean)

    if not seed:
        return {
            "status": "no_data",
            "onion": clean,
            "matched_actor": matched_actor,
            "indicators": None,
            "confidence": 0,
            "note": (
                "No misconfiguration indicators on file for this service. "
                "This endpoint is currently seeded with a handful of demo records; "
                "production would run a live scan (server-status probing, "
                "certificate-transparency cross-reference, banner grab) here."
            ),
        }

    return {
        "status": "seeded_demo",
        "onion": clean,
        "matched_actor": matched_actor,
        "indicators": {
            "exposed_server_status": seed["exposed_server_status"],
            "ssl_certificate_reused_on_clearnet": seed["ssl_certificate_reused_on_clearnet"],
            "default_service_banner": seed["default_service_banner"],
            "descriptor_inconsistency": seed["descriptor_inconsistency"],
        },
        "likely_clearnet_origin": seed["likely_clearnet_origin"],
        "confidence": seed["confidence"],
        "note": "Synthetic demo data illustrating the intended output shape — not a verified live scan result.",
    }



# Persona / stylometric linkage — live computation using the NLP engines.
# No more hardcoded seed: any two aliases can be compared in real time.

def _get_actor_corpus(alias: str) -> str:
    """
    Build a text corpus for an alias by combining:
      1. Their OSINT database stylometry markers + any past_posts
      2. All dark-web posts in the mock feed (and user feed) attributed to this alias
    Returns a lower-cased blob suitable for TF-IDF ingestion.
    """
    alias_lower = alias.strip().lower()

    # Look up the actor profile by surface_alias
    matched_profile = next(
        (a for a in _osint_data if a.get("surface_alias", "").lower() == alias_lower),
        None,
    )
    corpus_parts: list = []

    if matched_profile:
        corpus_parts += matched_profile.get("stylometry_markers", [])
        corpus_parts += matched_profile.get("past_posts", [])

    # Pull attributed posts from the mock feed
    try:
        with open("mock_feed.json", "r") as f:
            mock_posts = json.load(f)
        for post in mock_posts:
            if post.get("author", "").lower() == alias_lower:
                corpus_parts.append(post["content"])
    except Exception:
        pass

    # Pull attributed posts from the custom/user feed
    for post in _load_posts():
        if post.get("author", "").lower() == alias_lower:
            corpus_parts.append(post["content"])

    return " ".join(corpus_parts).lower()


@router.get("/persona/link")
def persona_link(
    alias_a: str = Query(..., description="Surface alias of the first persona"),
    alias_b: str = Query(..., description="Surface alias of the second persona"),
):
    """
    Live persona linkage using three complementary signals:

    1. TF-IDF character n-gram cosine similarity on the combined post corpora
       of both aliases — measures shared linguistic fingerprint.
    2. Jaro-Winkler string edit distance between the two handle strings —
       detects handle mutation / rebrand patterns (e.g. Garnet → Bravo).
    3. Shared TTP vocabulary intersection — how many tactical terms appear
       in both personas' attributed posts.

    Migration confidence = weighted combination of all three signals.
    """
    corpus_a = _get_actor_corpus(alias_a)
    corpus_b = _get_actor_corpus(alias_b)

    # 1. TF-IDF stylometric similarity (0–100 %)
    raw_stylo = _correlator.stylo_engine.score_pair(corpus_a, corpus_b)
    stylometric_similarity = round(raw_stylo * 100, 1)

    # 2. Jaro-Winkler alias edit distance (0–100 %)
    alias_edit = round(_correlator.alias_engine.compare(alias_a, alias_b) * 100, 1)

    # 3. Shared TTPs
    shared_ttps = _correlator.ttp_engine.shared_ttps(corpus_a, corpus_b)
    # Normalise: 5 shared TTPs → 50 %, 10 → 100 %
    ttp_overlap_score = min(100.0, round(len(shared_ttps) * 10.0, 1))

    # Migration confidence: weighted average of the three signals.
    # Stylometry carries the most weight (behavioural fingerprint),
    # alias similarity flags rebranding, TTP overlap confirms role continuity.
    migration_confidence = round(
        stylometric_similarity * 0.50 +
        alias_edit             * 0.25 +
        ttp_overlap_score      * 0.25,
        1,
    )

    # Verdict classification
    if migration_confidence >= 70:
        verdict = "High likelihood of persona migration (rebrand/split pattern)"
    elif migration_confidence >= 45:
        verdict = "Plausible overlap — possible shared operator or rebrand"
    elif migration_confidence >= 20:
        verdict = "Weak overlap — likely distinct personas with overlapping vocabulary"
    else:
        verdict = "No significant linkage detected"

    return {
        "status": "live",
        "alias_a": alias_a,
        "alias_b": alias_b,
        "stylometric_similarity": stylometric_similarity,
        "alias_edit_distance": alias_edit,
        "ttp_overlap_score": ttp_overlap_score,
        "shared_ttps": shared_ttps,
        "migration_confidence": migration_confidence,
        "verdict": verdict,
        "methodology": {
            "stylometry": "TF-IDF character n-gram (3–5) cosine similarity on attributed post corpora",
            "alias_matching": "Jaro-Winkler string edit distance on handle strings",
            "ttp_alignment": f"{len(shared_ttps)} shared tactical terms × 10% (capped at 100%)",
        },
        "note": (
            "Computed live using the NLP engine — not demo seed data. "
            "Corpus size is proportional to indexed post history for each alias."
        ),
    }

