import re

class ThreatExtractor:
    def __init__(self):
        # Precise CTI identifiers across surface and underground channels
        self.patterns = {
            "btc_wallets": r"\b(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
            "xmr_wallets": r"\b[48][0-9a-zA-Z]{94}\b",
            "usdt_wallets": r"\bT[a-zA-Z0-9]{33}\b",
            "emails": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
            "onion_urls": r"\bhttps?://[a-z2-7]{16,56}\.onion\b|\b[a-z2-7]{16,56}\.onion\b",
            "tox_ids": r"\b[0-9a-fA-F]{76}\b",
            "telegram_handles": r"(?<=telegram:\s)@?[a-zA-Z0-9_]{5,32}\b|(?<=t\.me/)[a-zA-Z0-9_]{5,32}\b",
            "jabber_ids": r"\b[a-zA-Z0-9_.+-]+@(?:exploit\.in|jabber\.ru|xmpp\.jp|thesecure\.biz)\b"
        }

    def extract(self, raw_text: str) -> dict:
        results = {}
        for key, pattern in self.patterns.items():
            matches = re.findall(pattern, raw_text, flags=re.IGNORECASE)
            results[key] = sorted(list(set(matches)))
        return results

    def classify_query(self, query: str) -> str:
        """Determines the indicator type for the UI badge automatically."""
        q = query.strip()
        if not q:
            return "EMPTY"
        if len(q.split()) > 3:
            return "RAW_TEXT_STYLOMETRY"
        if re.fullmatch(self.patterns["btc_wallets"], q, flags=re.IGNORECASE):
            return "BITCOIN_WALLET"
        if re.fullmatch(self.patterns["xmr_wallets"], q, flags=re.IGNORECASE):
            return "MONERO_WALLET"
        if re.fullmatch(self.patterns["usdt_wallets"], q, flags=re.IGNORECASE):
            return "USDT_TRC20_WALLET"
        if re.fullmatch(self.patterns["emails"], q, flags=re.IGNORECASE):
            return "EMAIL_ADDRESS"
        if re.fullmatch(self.patterns["tox_ids"], q, flags=re.IGNORECASE):
            return "TOX_ID"
        if re.search(r"\.onion\b", q, flags=re.IGNORECASE):
            return "ONION_INFRASTRUCTURE"
        return "ALIAS_OR_NAME"
