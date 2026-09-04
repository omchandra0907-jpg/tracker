import re

class ThreatExtractor:
    def __init__(self):
        # Precise regex patterns for critical cybersecurity identifiers
        self.patterns = {
            "btc_wallets": r"\b(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
            "emails": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
            "onion_urls": r"\bhttp[s]?://[a-z2-7]{16,56}\.onion\b",
        }

    def extract(self, raw_text: str) -> dict:
        results = {}
        for key, pattern in self.patterns.items():
            matches = re.findall(pattern, raw_text)
            # Remove duplicates and store as a clean list
            results[key] = sorted(list(set(matches)))
        return results
