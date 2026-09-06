"""
correlator.py
─────────────
Dual-Tier Evidence Fusion Engine for the DoxInt de-anonymization system.

Every percentage displayed in the frontend Identity Confidence Matrix maps
1-to-1 to a calculable, explainable mathematical operation:

  Tier 1 — Deterministic Identity IOCs (cryptographic / graph proof)
  ┌───────────────────────────────────────┬────────────┐
  │ Dimension                             │ Max Score  │
  ├───────────────────────────────────────┼────────────┤
  │ Crypto Networks   (wallet match)      │   100%     │
  │ Email Selectors   (mailbox match)     │   100%     │
  │ Encrypted Comms   (Tox/Jabber/TG)    │   100%     │
  │ Dark Infrastructure (.onion match)   │   100%     │
  └───────────────────────────────────────┴────────────┘

  Tier 2 — Probabilistic Behavioral Signals (NLP / statistics)
  ┌───────────────────────────────────────┬────────────┐
  │ Dimension                             │ Max Score  │
  ├───────────────────────────────────────┼────────────┤
  │ Stylometry  (TF-IDF char n-gram cos)  │    30%     │
  │ Alias Cross-Match (Jaro-Winkler)      │   100%     │
  │ Threat TTP Alignment (set intersect)  │   100%     │
  │ Temporal Activity (Gaussian Circadian)│   100%     │
  └───────────────────────────────────────┴────────────┘

  Composite Confidence Formula
  ─────────────────────────────
  If ANY hard IOC matches (Tier 1 base > 0):
    score = min(100, hard_base + stylo×0.15 + alias×0.05 + ttp×0.05 + temporal×0.05)

  If NO hard IOC matches (anonymous / soft intercept):
    score = stylo×0.40 + alias×0.30 + ttp×0.20 + temporal×0.10
    (capped at 65 — prevents false certainty without cryptographic proof)
"""

import os
import json
from collections import defaultdict
from dotenv import load_dotenv

from nlp_engine import (
    StylometryVectorizer,
    AliasMatcher,
    TTPAligner,
    TemporalCorrelator,
)

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

        # ── Tier 1: inverted indexes for deterministic IOC lookups ──
        self.wallet_index = defaultdict(list)
        self.email_index = defaultdict(list)
        self.comms_index = defaultdict(list)
        self.onion_index = defaultdict(list)
        self.alias_index = defaultdict(list)

        self._build_inverted_indexes()

        # ── Tier 2: NLP engines (initialised once at startup) ──
        self._stylo = StylometryVectorizer(self.osint_data)
        self._alias_matcher = AliasMatcher(self.osint_data)
        self._ttp = TTPAligner(self.osint_data)
        self._temporal = TemporalCorrelator()

        # ── Optional Neo4j graph backend ──
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
            for w in actor.get("known_wallets", []):
                self.wallet_index[w].append(name)
            for em in actor.get("known_emails", []):
                self.email_index[em.lower()].append(name)
            for cm in actor.get("known_comms", []):
                self.comms_index[cm.lower()].append(name)
            for on in actor.get("known_onions", []):
                self.onion_index[on.lower()].append(name)
            if "surface_alias" in actor:
                self.alias_index[actor["surface_alias"].lower()].append(name)

    # ──────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────

    def calculate_risk(self, darkweb_indicators: dict, raw_text: str = "",
                       post_author: str = "", timestamp: str = None) -> list:
        """
        Main correlation method. Tries Neo4j graph first; falls back to the
        inverted-index engine.  Both paths now incorporate all 8 NLP scores.
        """
        if self.neo4j_driver:
            try:
                return self._correlate_graph(darkweb_indicators, raw_text,
                                             post_author, timestamp)
            except Exception:
                pass
        return self._correlate_inverted_index(darkweb_indicators, raw_text,
                                              post_author, timestamp)

    # ──────────────────────────────────────────────────────────────────────
    # Composite confidence formula (shared by both correlation paths)
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _composite_score(crypto: float, email: float, comms: float,
                         infra: float, alias_ioc: float,
                         stylo: float, alias_nlp: float,
                         ttp: float, temporal: float) -> int:
        """
        Two-tier confidence fusion.

        Tier 1 (hard IOCs): if any deterministic indicator matched, we have
        cryptographic or registry-anchored proof.  Behavioral signals provide
        an upward corroboration boost, capped so the final score cannot exceed
        100%.

        Tier 2 (soft / anonymous): no hard proof exists — we return a
        probabilistic attribution lead capped at 65 to prevent false certainty.

        All scores fed in are already in [0, 100] (stylo is [0, 30]).
        """
        hard_base = max(crypto, email, comms, infra, alias_ioc)

        if hard_base > 0:
            # Behavioral signals add up to 30% boost on top of the hard base.
            boost = (
                stylo   * 0.15 +   # max +4.5  (stylo already capped at 30)
                alias_nlp * 0.05 + # max +5.0
                ttp     * 0.05 +   # max +5.0
                temporal * 0.05    # max +5.0
            )
            return min(100, round(hard_base + boost))
        else:
            # Soft attribution lead from behavioral signals only.
            soft = (
                stylo     * 0.40 +
                alias_nlp * 0.30 +
                ttp       * 0.20 +
                temporal  * 0.10
            )
            return min(65, round(soft))

    # ──────────────────────────────────────────────────────────────────────
    # Path A: Neo4j graph correlation
    # ──────────────────────────────────────────────────────────────────────

    def _correlate_graph(self, iocs: dict, raw_text: str,
                         post_author: str, timestamp) -> list:
        wallets = iocs.get("btc_wallets", []) + iocs.get("xmr_wallets", []) + iocs.get("usdt_wallets", [])
        emails = [e.lower() for e in iocs.get("emails", [])]
        comms = [c.lower() for c in (
            iocs.get("tox_ids", []) + iocs.get("jabber_ids", []) + iocs.get("telegram_handles", [])
        )]
        onions = [
            o.lower().replace("http://", "").replace("https://", "").strip("/")
            for o in iocs.get("onion_urls", [])
        ]

        query = """
        MATCH (a:Actor)
        OPTIONAL MATCH (a)-[:OWNS_WALLET]->(w:Wallet)    WHERE w.address IN $wallets
        OPTIONAL MATCH (a)-[:USES_EMAIL]->(e:Email)      WHERE toLower(e.address) IN $emails
        OPTIONAL MATCH (a)-[:USES_COMMS]->(c:Comms)      WHERE toLower(c.handle) IN $comms
        OPTIONAL MATCH (a)-[:OWNS_INFRA]->(i:Infrastructure) WHERE toLower(i.domain) IN $onions

        WITH a,
             [x IN collect(DISTINCT w.address) WHERE x IS NOT NULL] AS matched_wallets,
             [x IN collect(DISTINCT e.address) WHERE x IS NOT NULL] AS matched_emails,
             [x IN collect(DISTINCT c.handle)  WHERE x IS NOT NULL] AS matched_comms,
             [x IN collect(DISTINCT i.domain)  WHERE x IS NOT NULL] AS matched_infra
        RETURN a.name AS real_name, a.alias AS surface_alias, a.platform AS platform,
               matched_wallets, matched_emails, matched_comms, matched_infra
        """

        # Pre-compute NLP scores once for this intercept
        stylo_scores   = self._stylo.score_all(raw_text)
        alias_scores   = self._alias_matcher.score_all(post_author)
        ttp_data       = self._ttp.score_all(raw_text)
        temporal_scores = self._temporal.score_all(timestamp)

        matches = []
        with self.neo4j_driver.session() as session:
            records = session.run(query, wallets=wallets, emails=emails,
                                  comms=comms, onions=onions)
            for r in records:
                name = r["real_name"]

                # Tier 1 scores
                crypto = 100 if r["matched_wallets"] else 0
                email  = 100 if r["matched_emails"] else 0
                co     = 100 if r["matched_comms"] else 0
                infra  = 100 if r["matched_infra"] else 0

                # Tier 2 NLP scores
                stylo    = stylo_scores.get(name, 0)
                alias_s  = alias_scores.get(name, 0)
                ttp_info = ttp_data.get(name, {"score": 0, "matched_ttps": []})
                ttp_s    = ttp_info["score"]
                temp_s   = temporal_scores.get(name, 0)

                evidence = []
                for w in r["matched_wallets"]: evidence.append(f"Blockchain Match: {w}")
                for em in r["matched_emails"]: evidence.append(f"Email Match: {em}")
                for cm in r["matched_comms"]:  evidence.append(f"Comms Match: {cm}")
                for inf in r["matched_infra"]: evidence.append(f"Infrastructure Match: {inf}")
                for t in ttp_info.get("matched_ttps", []):
                    evidence.append(f"TTP Match: {t}")

                # Only include if at least one dimension has a signal
                if crypto or email or co or infra or stylo or alias_s or ttp_s:
                    final_conf = self._composite_score(
                        crypto, email, co, infra, 0,
                        stylo, alias_s, ttp_s, temp_s
                    )
                    if final_conf > 0:
                        matches.append({
                            "suspect_name": name,
                            "surface_platform": r["platform"] or "Underground Channel",
                            "confidence_score": final_conf,
                            "evidence": evidence,
                            "breakdown": {
                                "crypto":         crypto,
                                "email":          email,
                                "comms":          co,
                                "infrastructure": infra,
                                "stylometry":     round(stylo, 1),
                                "alias":          round(alias_s, 1),
                                "ttps":           round(ttp_s, 1),
                                "temporal":       round(temp_s, 1),
                            },
                        })

        return sorted(matches, key=lambda x: x["confidence_score"], reverse=True)

    # ──────────────────────────────────────────────────────────────────────
    # Path B: In-memory inverted index correlation
    # ──────────────────────────────────────────────────────────────────────

    def _correlate_inverted_index(self, iocs: dict, raw_text: str,
                                  post_author: str = "", timestamp=None) -> list:
        """
        Full 8-dimension correlation using in-memory indexes and NLP engines.
        """
        # ── Tier 1: deterministic IOC hits ──────────────────────────────
        scores: dict = defaultdict(lambda: {
            "crypto": 0, "email": 0, "comms": 0, "infrastructure": 0,
            "alias_ioc": 0, "evidence": [],
        })

        for w in (iocs.get("btc_wallets", []) + iocs.get("xmr_wallets", []) +
                  iocs.get("usdt_wallets", [])):
            if w in self.wallet_index:
                for s in self.wallet_index[w]:
                    scores[s]["crypto"] = 100
                    scores[s]["evidence"].append(f"Blockchain Match: {w}")

        for em in iocs.get("emails", []):
            if em.lower() in self.email_index:
                for s in self.email_index[em.lower()]:
                    scores[s]["email"] = 100
                    scores[s]["evidence"].append(f"Email Match: {em}")

        for cm in (iocs.get("tox_ids", []) + iocs.get("jabber_ids", []) +
                   iocs.get("telegram_handles", [])):
            if cm.lower() in self.comms_index:
                for s in self.comms_index[cm.lower()]:
                    scores[s]["comms"] = 100
                    scores[s]["evidence"].append(f"Comms Match: {cm}")

        for on in iocs.get("onion_urls", []):
            clean_on = on.lower().replace("http://", "").replace("https://", "").strip("/")
            if clean_on in self.onion_index:
                for s in self.onion_index[clean_on]:
                    scores[s]["infrastructure"] = 100
                    scores[s]["evidence"].append(f"Infrastructure Match: {on}")

        # ── Tier 2: NLP scores (computed once per intercept) ──────────
        stylo_scores    = self._stylo.score_all(raw_text)
        alias_scores    = self._alias_matcher.score_all(post_author)
        ttp_data        = self._ttp.score_all(raw_text)
        temporal_scores = self._temporal.score_all(timestamp)

        # Merge all actor names that appear in ANY scoring dimension
        all_actors: set = (
            set(scores.keys())
            | set(stylo_scores.keys())
            | set(alias_scores.keys())
            | {n for n, d in ttp_data.items() if d["score"] > 0}
        )

        ranked: list = []
        for name in all_actors:
            tier1 = scores[name]
            crypto    = tier1["crypto"]
            email     = tier1["email"]
            co        = tier1["comms"]
            infra     = tier1["infrastructure"]
            alias_ioc = tier1["alias_ioc"]
            evidence  = list(tier1["evidence"])

            stylo    = stylo_scores.get(name, 0)
            alias_s  = alias_scores.get(name, 0)
            ttp_info = ttp_data.get(name, {"score": 0, "matched_ttps": []})
            ttp_s    = ttp_info["score"]
            temp_s   = temporal_scores.get(name, 0)

            # Annotate evidence with TTP matches
            for t in ttp_info.get("matched_ttps", []):
                evidence.append(f"TTP Match: {t}")

            final_conf = self._composite_score(
                crypto, email, co, infra, alias_ioc,
                stylo, alias_s, ttp_s, temp_s
            )

            if final_conf > 0:
                profile = self.actor_lookup.get(name, {})
                ranked.append({
                    "suspect_name": name,
                    "surface_platform": profile.get("platform", "Underground Channel"),
                    "confidence_score": final_conf,
                    "evidence": evidence,
                    "breakdown": {
                        "crypto":         crypto,
                        "email":          email,
                        "comms":          co,
                        "infrastructure": infra,
                        "stylometry":     round(stylo, 1),
                        "alias":          round(alias_s, 1),
                        "ttps":           round(ttp_s, 1),
                        "temporal":       round(temp_s, 1),
                    },
                })

        return sorted(ranked, key=lambda x: x["confidence_score"], reverse=True)

    # ──────────────────────────────────────────────────────────────────────
    # Convenience accessors used by intel_routes.py
    # ──────────────────────────────────────────────────────────────────────

    @property
    def stylo_engine(self) -> StylometryVectorizer:
        return self._stylo

    @property
    def alias_engine(self) -> AliasMatcher:
        return self._alias_matcher

    @property
    def ttp_engine(self) -> TTPAligner:
        return self._ttp
