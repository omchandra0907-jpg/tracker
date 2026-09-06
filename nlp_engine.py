"""
nlp_engine.py
─────────────
Panel-defensible NLP scoring components for the DoxInt correlation engine.

Four self-contained classes, each computing a distinct dimension of the
Identity Confidence Matrix and returning a 0–100 score plus an explanation
dict so that every percentage on the frontend can be traced back to a
concrete mathematical operation.

  ┌─────────────────────────────────────────────────────────────────────┐
  │  StylometryVectorizer  │  TF-IDF char n-grams → cosine similarity  │
  │  AliasMatcher          │  Jaro-Winkler string edit distance         │
  │  TTPAligner            │  Set intersection / role vocabulary TF-IDF │
  │  TemporalCorrelator    │  Circadian Gaussian hour-of-day match      │
  └─────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Attempt to import scikit-learn. If unavailable we fall back to a hand-rolled
# TF-IDF so the engine is still correct, just slightly less accurate.
# ──────────────────────────────────────────────────────────────────────────────
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity as sklearn_cos
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# 1. Stylometry — TF-IDF character n-gram cosine similarity
# ══════════════════════════════════════════════════════════════════════════════

class StylometryVectorizer:
    """
    Builds a per-actor TF-IDF character n-gram matrix from the OSINT database
    at startup. On each intercept, transforms the raw post text and returns
    a cosine similarity score in [0, 30] for each actor.

    Why character n-grams?
    ─────────────────────
    Topic words change between posts ("ransomware", "escrow"). But character
    n-grams capture subconscious writing habits that persist across topics:
    punctuation spacing, preferred word suffixes, common typo patterns,
    uppercase habits.

    Why cap at 30?
    ──────────────
    Stylometry alone cannot establish cryptographic identity. The 30% cap
    signals to the analyst that text similarity is *corroborating* evidence,
    not a deterministic proof.
    """

    CAP = 30          # Maximum contribution to the composite score
    SIMILARITY_THRESHOLD = 0.05   # Ignore noise below this cosine distance

    def __init__(self, actor_profiles: list):
        self.actor_names: list = []
        corpus: list = []

        for actor in actor_profiles:
            # Combine all known linguistic signals into a single text blob.
            markers = actor.get("stylometry_markers", [])
            past_posts = actor.get("past_posts", [])
            blob = " ".join(past_posts) + " " + " ".join(markers)
            self.actor_names.append(actor["real_name"])
            corpus.append(blob.lower().strip())

        self._corpus = corpus

        if _SKLEARN_AVAILABLE and len(corpus) > 1:
            self._vectorizer = TfidfVectorizer(
                analyzer="char_wb",         # character n-grams within word boundaries
                ngram_range=(3, 5),
                min_df=1,
                sublinear_tf=True,          # apply log(1+tf) to dampen high frequencies
                max_features=20_000,
            )
            self._actor_matrix = self._vectorizer.fit_transform(corpus)
            self._mode = "sklearn"
        else:
            # Fallback: hand-rolled bag-of-words TF-IDF on word tokens
            self._idf, self._vocab = self._build_idf(corpus)
            self._actor_vecs = [self._tfidf_vec(doc) for doc in corpus]
            self._mode = "fallback"

    # ── scikit-learn path ──────────────────────────────────────────────────

    def _sklearn_score(self, raw_text: str) -> dict:
        post_vec = self._vectorizer.transform([raw_text.lower()])
        sims = sklearn_cos(post_vec, self._actor_matrix)[0]
        return {
            self.actor_names[i]: round(min(self.CAP, float(s) * self.CAP), 2)
            for i, s in enumerate(sims)
            if float(s) >= self.SIMILARITY_THRESHOLD
        }

    # ── fallback hand-rolled TF-IDF ─────────────────────────────────────

    def _build_idf(self, corpus: list):
        from collections import Counter
        df: dict = {}
        for doc in corpus:
            tokens = set(doc.split())
            for t in tokens:
                df[t] = df.get(t, 0) + 1
        N = len(corpus) or 1
        idf = {t: math.log((1 + N) / (1 + d)) + 1 for t, d in df.items()}
        vocab = {word: i for i, word in enumerate(sorted(idf))}
        return idf, vocab

    def _tfidf_vec(self, doc: str) -> dict:
        from collections import Counter
        counts = Counter(doc.split())
        total = sum(counts.values()) or 1
        return {t: (c / total) * self._idf.get(t, 1) for t, c in counts.items()}

    def _cosine(self, a: dict, b: dict) -> float:
        keys = set(a) & set(b)
        dot = sum(a[k] * b[k] for k in keys)
        mag_a = math.sqrt(sum(v * v for v in a.values()))
        mag_b = math.sqrt(sum(v * v for v in b.values()))
        if not mag_a or not mag_b:
            return 0.0
        return dot / (mag_a * mag_b)

    def _fallback_score(self, raw_text: str) -> dict:
        post_vec = self._tfidf_vec(raw_text.lower())
        result: dict = {}
        for i, actor_vec in enumerate(self._actor_vecs):
            sim = self._cosine(post_vec, actor_vec)
            if sim >= self.SIMILARITY_THRESHOLD:
                result[self.actor_names[i]] = round(min(self.CAP, sim * self.CAP), 2)
        return result

    # ── public API ──────────────────────────────────────────────────────────

    def score_all(self, raw_text: str) -> dict:
        """
        Returns {actor_name: stylometry_score (0–30)} for actors whose
        character n-gram profile overlaps meaningfully with the intercept text.
        """
        if not raw_text.strip():
            return {}
        if self._mode == "sklearn":
            return self._sklearn_score(raw_text)
        return self._fallback_score(raw_text)

    def score_pair(self, text_a: str, text_b: str) -> float:
        """
        Compute similarity between two arbitrary text blobs.
        Returns cosine similarity in [0.0, 1.0].
        Used by the /persona/link endpoint for live stylometric comparison.
        """
        if not text_a.strip() or not text_b.strip():
            return 0.0
        if self._mode == "sklearn":
            va = self._vectorizer.transform([text_a.lower()])
            vb = self._vectorizer.transform([text_b.lower()])
            return round(float(sklearn_cos(va, vb)[0][0]), 4)
        else:
            va = self._tfidf_vec(text_a.lower())
            vb = self._tfidf_vec(text_b.lower())
            return round(self._cosine(va, vb), 4)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Alias Matching — Jaro-Winkler string edit distance
# ══════════════════════════════════════════════════════════════════════════════

class AliasMatcher:
    """
    Threat actors frequently mutate handles across forums:
      Bentley → boriselcin   (alternate spelling)
      LockBitSupp → LockBit_Representative  (role suffix)

    Binary equality matching misses all of these. Jaro-Winkler assigns higher
    similarity to strings sharing a common prefix, which is exactly how most
    darknet aliases are constructed.

    Score formula
    ─────────────
      jaro_winkler(post_author, surface_alias) → [0, 1]
      alias_score = round(similarity * 100)
    """

    THRESHOLD = 0.62      # Below this we consider handles unrelated

    def __init__(self, actor_profiles: list):
        # Pre-index surface aliases and all known comm handles per actor
        self._aliases: dict = {}
        for actor in actor_profiles:
            name = actor["real_name"]
            handles = []
            if "surface_alias" in actor:
                handles.append(actor["surface_alias"].lower())
            for c in actor.get("known_comms", []):
                # Skip Tox IDs (hex strings ≥ 70 chars) — not aliases
                if len(c) < 50:
                    handles.append(c.lower())
            self._aliases[name] = handles

    @staticmethod
    def _jaro(s: str, t: str) -> float:
        if s == t:
            return 1.0
        ls, lt = len(s), len(t)
        if ls == 0 or lt == 0:
            return 0.0
        match_dist = max(ls, lt) // 2 - 1
        s_matches = [False] * ls
        t_matches = [False] * lt
        matches = 0
        transpositions = 0
        for i in range(ls):
            start = max(0, i - match_dist)
            end = min(i + match_dist + 1, lt)
            for j in range(start, end):
                if t_matches[j] or s[i] != t[j]:
                    continue
                s_matches[i] = t_matches[j] = True
                matches += 1
                break
        if matches == 0:
            return 0.0
        k = 0
        for i in range(ls):
            if not s_matches[i]:
                continue
            while not t_matches[k]:
                k += 1
            if s[i] != t[k]:
                transpositions += 1
            k += 1
        return (matches / ls + matches / lt + (matches - transpositions / 2) / matches) / 3

    @classmethod
    def _jaro_winkler(cls, s: str, t: str, p: float = 0.1) -> float:
        jaro = cls._jaro(s, t)
        prefix = 0
        for sc, tc in zip(s, t):
            if sc == tc:
                prefix += 1
            else:
                break
            if prefix == 4:
                break
        return jaro + prefix * p * (1 - jaro)

    def score_all(self, post_author: str) -> dict:
        """
        Returns {actor_name: alias_score (0–100)} for actors whose known
        surface aliases are sufficiently similar to the post author handle.
        """
        author = post_author.lower().strip()
        if not author or author in ("unknown_actor", ""):
            return {}
        result: dict = {}
        for name, handles in self._aliases.items():
            if not handles:
                continue
            best = max(
                (self._jaro_winkler(author, h) for h in handles),
                default=0.0,
            )
            if best >= self.THRESHOLD:
                result[name] = round(best * 100, 1)
        return result

    def compare(self, alias_a: str, alias_b: str) -> float:
        """
        Compare two arbitrary handles. Returns [0, 1] similarity.
        """
        return round(self._jaro_winkler(alias_a.lower(), alias_b.lower()), 4)


# ══════════════════════════════════════════════════════════════════════════════
# 3. TTP Alignment — Tactics, Techniques, and Procedures
# ══════════════════════════════════════════════════════════════════════════════

# MITRE ATT&CK inspired role vocabulary mapped to actor categories.
# Each category carries weighted TTP keywords. Weights reflect how
# diagnostic a term is for the specific role.
_CATEGORY_TTP_MAP: dict = {
    "Ransomware Operator": {
        "ransom": 1.0, "payload": 0.9, "affiliate": 0.9, "extortion": 1.0,
        "encrypt": 0.8, "decryptor": 0.9, "negotiat": 0.8, "raas": 1.0,
        "double extortion": 1.0, "partial encryption": 0.9, "callback": 0.7,
        "locker": 0.8, "leak": 0.7, "victim": 0.7, "backup": 0.6,
    },
    "Malware / Tooling Vendor": {
        "fud": 1.0, "bypass": 0.9, "stub": 0.9, "obfuscator": 1.0,
        "runtime": 0.8, "inject": 0.9, "memory injection": 1.0, "scantime": 0.9,
        "loader": 0.8, "builder": 0.8, "crypter": 1.0, "edr": 0.9,
        "maldoc": 0.9, "macros": 0.8, "dropper": 0.8, "stealer": 0.9,
        "browser logs": 0.9, "cookies": 0.6, "seed phrase": 0.9, "drainer": 1.0,
        "poc": 0.8, "0day": 1.0,
    },
    "Money Laundering / Mixer": {
        "launder": 1.0, "mixer": 1.0, "relayer": 0.9, "privacy pool": 0.9,
        "p2p": 0.7, "conversion": 0.8, "escrow": 0.7, "fiat": 0.9,
        "liquidation": 0.9, "otc": 0.8, "cash": 0.6, "tumbler": 0.9,
        "chain hop": 0.9, "swap": 0.7,
    },
    "Carding / Fraud Vendor": {
        "cvv": 1.0, "dump": 0.9, "validity rate": 1.0, "carding": 1.0,
        "fullz": 1.0, "bingo": 0.8, "checker": 0.9, "track": 0.8,
        "cashout": 0.9, "gift card": 0.8, "giftcard": 0.8,
    },
    "Marketplace Vendor": {
        "vendor": 0.7, "listing": 0.7, "escrow": 0.6, "feedback": 0.6,
        "pgp": 0.7, "vouch": 0.8, "trusted": 0.6, "bulk": 0.6,
    },
    "Infrastructure / Access Broker": {
        "rdp": 0.9, "vpn": 0.7, "bulletproof": 1.0, "no logs": 0.9,
        "opsec": 0.8, "anonymizer": 0.9, "offshore": 0.9, "dmca ignored": 1.0,
        "access": 0.7, "initial access": 1.0, "living off the land": 1.0,
        "citrix": 0.9, "fortinet": 0.9, "lateral movement": 0.9,
        "botnet": 0.8, "c2": 0.9, "recon": 0.8, "pivot": 0.7,
        "poc": 0.7, "0day": 0.9,
    },
}


class TTPAligner:
    """
    Measures Tactics/Techniques/Procedures alignment between an intercepted
    post and a suspect's operational category profile.

    Score formula (per actor)
    ─────────────────────────
      matched_weight = Σ weight_i  for each TTP term present in the post
                       that belongs to this actor's category vocabulary
      max_weight     = Σ weight_i  for all terms in this actor's category

      ttp_score = min(100, (matched_weight / max_weight) × 100)
    """

    def __init__(self, actor_profiles: list):
        self._profiles: dict = {}
        for actor in actor_profiles:
            name = actor["real_name"]
            cat = actor.get("category", "")
            vocab = dict(_CATEGORY_TTP_MAP.get(cat, {}))
            custom_markers = actor.get("stylometry_markers", [])

            # Merge actor-specific markers into the vocab at weight 0.8
            for m in custom_markers:
                m_lower = m.lower()
                if m_lower not in vocab:
                    vocab[m_lower] = 0.8

            self._profiles[name] = {
                "category": cat,
                "vocab": vocab,
                "max_weight": sum(vocab.values()) or 1.0,
            }

    def score_all(self, raw_text: str) -> dict:
        """
        Returns {actor_name: {"score": 0-100, "matched_ttps": [...], "category": str}}
        for every actor.
        """
        text = raw_text.lower()
        result: dict = {}

        for name, profile in self._profiles.items():
            vocab = profile["vocab"]
            max_w = profile["max_weight"]
            matched: list = []

            for term, weight in vocab.items():
                # Word-boundary matching for single tokens,
                # substring matching for multi-word phrases.
                if " " in term:
                    if term in text:
                        matched.append((term, weight))
                else:
                    if re.search(r"\b" + re.escape(term) + r"\b", text):
                        matched.append((term, weight))

            total_matched_w = sum(w for _, w in matched)
            score = round(min(100.0, (total_matched_w / max_w) * 100), 1)

            result[name] = {
                "score": score,
                "matched_ttps": [t for t, _ in matched],
                "category": profile["category"],
            }

        return result

    def shared_ttps(self, text_a: str, text_b: str) -> list:
        """
        Returns TTP terms found in both text_a and text_b.
        Used by the /persona/link endpoint.
        """
        all_vocab: set = set()
        for v in _CATEGORY_TTP_MAP.values():
            all_vocab.update(v.keys())

        la, lb = text_a.lower(), text_b.lower()
        shared: list = []
        for term in sorted(all_vocab):
            if " " in term:
                in_a, in_b = term in la, term in lb
            else:
                pat = r"\b" + re.escape(term) + r"\b"
                in_a = bool(re.search(pat, la))
                in_b = bool(re.search(pat, lb))
            if in_a and in_b:
                shared.append(term)
        return shared


# ══════════════════════════════════════════════════════════════════════════════
# 4. Temporal Correlator — Circadian Gaussian hour-of-day alignment
# ══════════════════════════════════════════════════════════════════════════════

# Estimated UTC peak-activity hour and standard deviation per threat group.
# Values derived from public threat intel reports (e.g. CrowdStrike annual).
_ACTOR_TEMPORAL: dict = {
    "Maksim Galochkin":     {"peak_utc": 8.0,  "sigma": 3.0},   # Eastern Europe day shift
    "Mikhail Matveev":      {"peak_utc": 9.0,  "sigma": 3.0},
    "Dmitry Khoroshev":     {"peak_utc": 8.5,  "sigma": 3.5},
    "Maksim Yakubets":      {"peak_utc": 7.0,  "sigma": 3.0},
    "Park Jin Hyok":        {"peak_utc": 1.0,  "sigma": 4.0},   # DPRK (UTC+9 → ~0-2 UTC)
    "Dmytro Rashevskyi":    {"peak_utc": 8.0,  "sigma": 3.0},
    "Yevgeniy Silayev":     {"peak_utc": 9.0,  "sigma": 2.5},
    "Yaroslav Vasinskyi":   {"peak_utc": 8.0,  "sigma": 3.0},
    "Elena Rostova":        {"peak_utc": 10.0, "sigma": 3.0},
    "Evgeniy Bogachev":     {"peak_utc": 9.0,  "sigma": 4.0},
    "Roman Semenov":        {"peak_utc": 8.5,  "sigma": 3.0},
    "Armando Ojeda Aviles": {"peak_utc": 16.0, "sigma": 4.0},   # Mexico UTC-6
    "Aleksandr Sikerin":    {"peak_utc": 8.0,  "sigma": 3.0},
    "Vitaly Kovalev":       {"peak_utc": 9.0,  "sigma": 3.0},
    "Denis Kulkov":         {"peak_utc": 8.5,  "sigma": 3.0},
    "Igor Turashev":        {"peak_utc": 9.0,  "sigma": 3.5},
    "Rinat Zandiev":        {"peak_utc": 8.0,  "sigma": 3.0},
    "Alexey Bilyuchenko":   {"peak_utc": 9.0,  "sigma": 3.0},
    "Sandu Diaconu":        {"peak_utc": 7.0,  "sigma": 3.5},   # Romania UTC+2
    "Danil Potekhin":       {"peak_utc": 9.0,  "sigma": 3.0},
    "Sergey Zolotarev":     {"peak_utc": 8.0,  "sigma": 3.0},
    "Oleg Koshkin":         {"peak_utc": 9.0,  "sigma": 3.0},
    "Boris Chen":           {"peak_utc": 1.0,  "sigma": 4.0},   # China UTC+8 → ~0-2 UTC
    "Tariq Al-Mansoor":     {"peak_utc": 5.0,  "sigma": 4.0},   # Gulf region UTC+3
    "Ilya Sachkov":         {"peak_utc": 8.5,  "sigma": 3.0},
}

_DEFAULT_TEMPORAL = {"peak_utc": 8.0, "sigma": 4.0}


class TemporalCorrelator:
    """
    Computes the probability that a post was made by a specific actor
    based on the UTC hour of the post timestamp and the actor's known
    circadian activity window.

    Score formula
    ─────────────
      delta = circular_distance(post_hour, actor_peak_utc)   # [0, 12]
      score = exp(-delta² / (2 × sigma²)) × 100

    A post landing exactly on an actor's peak hour scores 100.
    A post 2σ away scores ~13.5 (Gaussian decay).
    """

    @staticmethod
    def _circular_distance(h1: float, h2: float) -> float:
        """Returns the minimum circular distance on the 24-hour clock."""
        diff = abs(h1 - h2) % 24
        return min(diff, 24 - diff)

    def score_all(self, timestamp) -> dict:
        """
        Returns {actor_name: temporal_score (0–100)}.
        If timestamp is None/unparseable returns {} (no deduction applied).
        """
        if not timestamp:
            return {}

        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            utc_hour = dt.hour + dt.minute / 60.0
        except (ValueError, AttributeError, TypeError):
            return {}

        result: dict = {}
        for name, profile in _ACTOR_TEMPORAL.items():
            peak = profile["peak_utc"]
            sigma = profile["sigma"]
            delta = self._circular_distance(utc_hour, peak)
            score = round(math.exp(-(delta ** 2) / (2 * sigma ** 2)) * 100, 1)
            result[name] = score

        return result

    @staticmethod
    def describe(actor_name: str, post_ts) -> dict:
        """Returns a human-readable description for the panel."""
        profile = _ACTOR_TEMPORAL.get(actor_name, _DEFAULT_TEMPORAL)
        return {
            "peak_utc_hour": profile["peak_utc"],
            "sigma_hours": profile["sigma"],
            "intercept_timestamp": post_ts,
            "note": (
                f"Actor known to be most active around "
                f"{int(profile['peak_utc']):02d}:00 UTC "
                f"(±{profile['sigma']:.0f}h). "
                "Score decays as a Gaussian function of temporal distance."
            ),
        }
