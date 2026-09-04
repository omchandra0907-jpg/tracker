import json
from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from extractor import ThreatExtractor
from correlator import CorrelationEngine
from custom_routes import router as custom_router

app = FastAPI(title="Dark Web Threat Actor De-Anonymization API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(custom_router)

extractor = ThreatExtractor()

with open("osint_db.json", "r") as f:
    osint_data = json.load(f)

correlator = CorrelationEngine(osint_data)

@app.get("/")
def serve_dashboard():
    return FileResponse("index.html")

@app.get("/api/v1/classify")
def classify_input(q: str = Query(..., description="Query string to classify")):
    return {"query": q, "detected_type": extractor.classify_query(q)}

@app.get("/api/v1/analyze")
def analyze_threats():
    with open("mock_feed.json", "r") as f:
        darkweb_posts = json.load(f)

    intelligence_report = []
    for post in darkweb_posts:
        extracted_iocs = extractor.extract(post["content"])
        suspects = correlator.calculate_risk(extracted_iocs, post["content"])
        
        intelligence_report.append({
            "darkweb_alias": post["author"],
            "extracted_indicators": extracted_iocs,
            "deanonymization_results": suspects
        })

    return {
        "status": "success",
        "threat_actors_analyzed": len(intelligence_report),
        "results": intelligence_report
    }
