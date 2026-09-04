import json
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from extractor import ThreatExtractor
from correlator import CorrelationEngine

app = FastAPI(title="Dark Web Threat Actor De-Anonymization API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
extractor = ThreatExtractor()

# Load OSINT database once at startup
with open("osint_db.json", "r") as f:
    osint_data = json.load(f)

correlator = CorrelationEngine(osint_data)

@app.get("/")
def serve_dashboard():
    return FileResponse("index.html")

@app.get("/api/v1/analyze")
def analyze_threats():
    with open("mock_feed.json", "r") as f:
        darkweb_posts = json.load(f)

    intelligence_report = []

    for post in darkweb_posts:
        # Extract hard indicators (BTC, Emails)
        extracted_iocs = extractor.extract(post["content"])
        
        # Pass BOTH the extracted IOCs and the raw text to the Brain
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
