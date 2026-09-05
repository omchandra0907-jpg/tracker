import os
import json
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

class CorrelationEngine:
    def __init__(self, osint_data: list = None):
        if osint_data is None:
            try:
                with open("osint_db.json", "r") as f:
                    self.osint_data = json.load(f)
            except Exception:
                self.osint_data = []
        else:
            self.osint_data = osint_data

        self.actor_lookup = {actor["real_name"]: actor for actor in self.osint_data}

        self.wallet_index = defaultdict(list)
        self.email_index = defaultdict(list)
        self.comms_index = defaultdict(list)
        self.onion_index = defaultdict(list)
        self.slang_index = defaultdict(list)
        self.alias_index = defaultdict(list)

        self._build_inverted_indexes()

        self.neo4j_driver = None
        if NEO4J_AVAILABLE:
            uri = os.getenv("NEO4J_URI")
            user = os.getenv("NEO4J_USERNAME")
            password = os.getenv("NEO4J_PASSWORD")
            if uri and user and password:
                try:
                    self.neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
                    self.neo4j_driver.verify_connectivity()
                except Exception:
                    self.neo4j_driver = None

    def _build_inverted_indexes(self):
        for actor in self.osint_data:
            name = actor["real_name"]
            for w in actor.get("known_wallets", []): self.wallet_index[w].append(name)
            for em in actor.get("known_emails", []): self.email_index[em.lower()].append(name)
            for cm in actor.get("known_comms", []): self.comms_index[cm.lower()].append(name)
            for on in actor.get("known_onions", []): self.onion_index[on.lower()].append(name)
            for sl in actor.get("stylometry_markers", []): self.slang_index[sl.lower()].append(name)
            if "surface_alias" in actor: self.alias_index[actor["surface_alias"].lower()].append(name)

    def calculate_risk(self, darkweb_indicators: dict, raw_text: str = "") -> list:
        if self.neo4j_driver:
            try:
                return self._correlate_graph(darkweb_indicators, raw_text)
            except Exception:
                pass
        return self._correlate_inverted_index(darkweb_indicators, raw_text)

    def _correlate_graph(self, iocs: dict, raw_text: str) -> list:
        wallets = iocs.get("btc_wallets", []) + iocs.get("xmr_wallets", []) + iocs.get("usdt_wallets", [])
        emails = [e.lower() for e in iocs.get("emails", [])]
        comms = [c.lower() for c in (iocs.get("tox_ids", []) + iocs.get("jabber_ids", []) + iocs.get("telegram_handles", []))]
        onions = [o.lower().replace("http://", "").replace("https://", "").strip("/") for o in iocs.get("onion_urls", [])]

        query = """
        MATCH (a:Actor)
        OPTIONAL MATCH (a)-[:OWNS_WALLET]->(w:Wallet) WHERE w.address IN $wallets
        OPTIONAL MATCH (a)-[:USES_EMAIL]->(e:Email) WHERE toLower(e.address) IN $emails
        OPTIONAL MATCH (a)-[:USES_COMMS]->(c:Comms) WHERE toLower(c.handle) IN $comms
        OPTIONAL MATCH (a)-[:OWNS_INFRA]->(i:Infrastructure) WHERE toLower(i.domain) IN $onions
        OPTIONAL MATCH (a)-[:KNOWN_SLANG]->(s:Slang) WHERE toLower($raw_text) CONTAINS toLower(s.term)
        
        WITH a,
             [x IN collect(DISTINCT w.address) WHERE x IS NOT NULL] AS matched_wallets,
             [x IN collect(DISTINCT e.address) WHERE x IS NOT NULL] AS matched_emails,
             [x IN collect(DISTINCT c.handle) WHERE x IS NOT NULL] AS matched_comms,
             [x IN collect(DISTINCT i.domain) WHERE x IS NOT NULL] AS matched_infra,
             [x IN collect(DISTINCT s.term) WHERE x IS NOT NULL] AS matched_slang
        WHERE size(matched_wallets) > 0 OR size(matched_emails) > 0 OR size(matched_comms) > 0 OR size(matched_infra) > 0 OR size(matched_slang) > 0
        RETURN a.name AS real_name, a.alias AS surface_alias, a.platform AS platform,
               matched_wallets, matched_emails, matched_comms, matched_infra, matched_slang
        """
        matches = []
        with self.neo4j_driver.session() as session:
            records = session.run(query, wallets=wallets, emails=emails, comms=comms, onions=onions, raw_text=raw_text)
            raw_lower = raw_text.lower()
            ttp_terms = ["escrow", "ransom", "payload", "affiliate", "botnet", "dump", "fud", "bypass"]
            found_ttps = [t for t in ttp_terms if t in raw_lower]
            
            for r in records:
                w_score = 100 if len(r["matched_wallets"]) > 0 else 0
                e_score = 85 if len(r["matched_emails"]) > 0 else 0
                c_score = 80 if len(r["matched_comms"]) > 0 else 0
                i_score = 75 if len(r["matched_infra"]) > 0 else 0
                s_score = min(len(r["matched_slang"]) * 15, 30)

                evidence = []
                for w in r["matched_wallets"]: evidence.append(f"Blockchain Match: {w}")
                for em in r["matched_emails"]: evidence.append(f"Email Match: {em}")
                for cm in r["matched_comms"]: evidence.append(f"Comms Match: {cm}")
                for inf in r["matched_infra"]: evidence.append(f"Infrastructure Match: {inf}")
                for sl in r["matched_slang"]: evidence.append(f"Stylometry Match: {sl}")

                hard_score = max(w_score, e_score, c_score, i_score)
                total = min(hard_score + s_score, 100) if (hard_score > 0 or s_score > 0) else 0
                ttp_score = min(len(found_ttps) * 15, 45) if (hard_score > 0 or s_score > 0) else 0

                if total > 0:
                    matches.append({
                        "suspect_name": r["real_name"],
                        "surface_platform": r["platform"] or "Underground Channel",
                        "confidence_score": total,
                        "evidence": evidence,
                        "breakdown": {
                            "crypto": w_score, "email": e_score, "comms": c_score,
                            "infrastructure": i_score, "stylometry": s_score,
                            "alias": 0, "ttps": ttp_score, "temporal": 0
                        }
                    })
        return sorted(matches, key=lambda x: x["confidence_score"], reverse=True)

    def _correlate_inverted_index(self, iocs: dict, raw_text: str) -> list:
        scores = defaultdict(lambda: {
            "crypto": 0, "email": 0, "comms": 0, "infrastructure": 0,
            "stylometry": 0, "alias": 0, "ttps": 0, "temporal": 0,
            "evidence": []
        })
        raw_lower = raw_text.lower()

        for w in (iocs.get("btc_wallets", []) + iocs.get("xmr_wallets", []) + iocs.get("usdt_wallets", [])):
            if w in self.wallet_index:
                for s in self.wallet_index[w]:
                    scores[s]["crypto"] = 100
                    scores[s]["evidence"].append(f"Blockchain Match: {w}")

        for em in iocs.get("emails", []):
            if em.lower() in self.email_index:
                for s in self.email_index[em.lower()]:
                    scores[s]["email"] = 85
                    scores[s]["evidence"].append(f"Email Match: {em}")

        for cm in (iocs.get("tox_ids", []) + iocs.get("jabber_ids", []) + iocs.get("telegram_handles", [])):
            if cm.lower() in self.comms_index:
                for s in self.comms_index[cm.lower()]:
                    scores[s]["comms"] = 80
                    scores[s]["evidence"].append(f"Comms Match: {cm}")

        for on in iocs.get("onion_urls", []):
            clean_on = on.lower().replace("http://", "").replace("https://", "").strip("/")
            if clean_on in self.onion_index:
                for s in self.onion_index[clean_on]:
                    scores[s]["infrastructure"] = 75
                    scores[s]["evidence"].append(f"Infrastructure Match: {on}")

        for sl, suspects in self.slang_index.items():
            if sl in raw_lower:
                for s in suspects:
                    scores[s]["stylometry"] += 15
                    scores[s]["evidence"].append(f"Stylometry Match: {sl}")

        ttp_terms = ["escrow", "ransom", "payload", "affiliate", "botnet", "dump", "fud", "bypass"]
        found_ttps = [t for t in ttp_terms if t in raw_lower]

        ranked = []
        for name, data in scores.items():
            bounded_stylo = min(data["stylometry"], 30)
            ttp_score = min(len(found_ttps) * 15, 45) if (data["crypto"] > 0 or data["email"] > 0 or bounded_stylo > 0) else 0

            hard_val = max(data["crypto"], data["email"], data["comms"], data["infrastructure"], data["alias"])
            final_conf = min(hard_val + bounded_stylo, 100) if (hard_val > 0 or bounded_stylo > 0) else 0

            if final_conf > 0:
                profile = self.actor_lookup.get(name, {})
                ranked.append({
                    "suspect_name": name,
                    "surface_platform": profile.get("platform", "Underground Channel"),
                    "confidence_score": final_conf,
                    "evidence": data["evidence"],
                    "breakdown": {
                        "crypto": data["crypto"],
                        "email": data["email"],
                        "comms": data["comms"],
                        "infrastructure": data["infrastructure"],
                        "stylometry": bounded_stylo,
                        "alias": data["alias"],
                        "ttps": ttp_score,
                        "temporal": 0
                    }
                })
        return sorted(ranked, key=lambda x: x["confidence_score"], reverse=True)
