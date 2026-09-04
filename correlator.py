class CorrelationEngine:
    def __init__(self, osint_data: list):
        self.osint_data = osint_data

    def calculate_risk(self, darkweb_indicators: dict, raw_text: str = "") -> list:
        matches = []
        
        for identity in self.osint_data:
            confidence_score = 0
            matched_evidence = []

            # Rule 1: Shared Cryptographic Evidence (+60 Points)
            for wallet in darkweb_indicators.get("btc_wallets", []):
                if wallet in identity.get("known_wallets", []):
                    confidence_score += 60
                    matched_evidence.append(f"Blockchain Match: {wallet}")

            # Rule 2: Shared Email Evidence (+40 Points)
            for email in darkweb_indicators.get("emails", []):
                if email in identity.get("known_emails", []):
                    confidence_score += 40
                    matched_evidence.append(f"Email Match: {email}")

            # Rule 3: Stylometry & Slang Match (+20 Points per word)
            for slang in identity.get("stylometry_markers", []):
                if slang.lower() in raw_text.lower():
                    confidence_score += 20
                    matched_evidence.append(f"Stylometry Match: {slang}")

            if confidence_score > 0:
                matches.append({
                    "suspect_name": identity["real_name"],
                    "surface_platform": identity["platform"],
                    "confidence_score": min(confidence_score, 100),
                    "evidence": matched_evidence
                })
        
        return sorted(matches, key=lambda x: x["confidence_score"], reverse=True)
