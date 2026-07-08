"""Natural-language semantic search.

Design-doc requirement: typing "google" should surface Gmail, G-Suite,
and Google Drive even when the keyword doesn't appear in the entry name.

Prototype approach (zero external dependencies):
  1. A curated semantic knowledge map linking brands/concepts to related
     services ("google" -> gmail, gsuite, drive, youtube...).
  2. Query normalization that strips natural-language filler so
     "my google accounts" reduces to "google".
  3. Fuzzy matching (difflib) to tolerate typos like "gogle".

Scores are blended so exact > semantic > fuzzy, and results are ranked.
A production build could swap in embedding vectors behind the same
`search()` signature.
"""
from __future__ import annotations

import difflib
import re

from .storage import Entry

# concept -> related tokens. Both directions are indexed at load time.
SEMANTIC_MAP: dict[str, set[str]] = {
    "google":    {"gmail", "gsuite", "g-suite", "googledrive", "drive",
                  "youtube", "gcloud", "googlecloud", "gcp", "android"},
    "microsoft": {"outlook", "hotmail", "office", "office365", "o365",
                  "onedrive", "teams", "azure", "xbox", "windows", "msn"},
    "apple":     {"icloud", "appstore", "itunes", "facetime", "macos"},
    "amazon":    {"aws", "prime", "kindle", "audible", "twitch"},
    "meta":      {"facebook", "instagram", "whatsapp", "messenger", "threads"},
    "bank":      {"banking", "chase", "wellsfargo", "bankofamerica", "boa",
                  "citi", "capitalone", "credit", "debit", "finance"},
    "email":     {"gmail", "outlook", "hotmail", "protonmail", "yahoo",
                  "mail", "icloud"},
    "social":    {"facebook", "instagram", "twitter", "x", "tiktok",
                  "reddit", "linkedin", "snapchat", "discord", "mastodon"},
    "gaming":    {"steam", "epicgames", "epic", "xbox", "playstation",
                  "psn", "nintendo", "battlenet", "riot", "origin", "ea",
                  "destiny", "bungie"},
    "work":      {"slack", "teams", "jira", "confluence", "zoom", "notion",
                  "asana", "trello", "github", "gitlab"},
    "streaming": {"netflix", "hulu", "spotify", "disney", "disneyplus",
                  "hbo", "max", "peacock", "paramount", "crunchyroll"},
    "school":    {"canvas", "blackboard", "university", "college", "edu",
                  "unt", "student"},
}

_FILLER = {"my", "the", "a", "an", "for", "all", "show", "me", "find",
           "get", "accounts", "account", "logins", "login", "passwords",
           "password", "credentials", "credential", "please", "of", "to"}


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


class SemanticSearch:
    def __init__(self, semantic_map: dict[str, set[str]] | None = None):
        m = semantic_map or SEMANTIC_MAP
        # index both directions: concept->services and service->siblings+concept
        self._related: dict[str, set[str]] = {}
        for concept, services in m.items():
            group = set(services) | {concept}
            for token in group:
                self._related.setdefault(token, set()).update(group - {token})

    def _entry_tokens(self, e: Entry) -> set[str]:
        toks = set(_tokens(e.title)) | set(_tokens(e.username)) \
             | set(_tokens(e.url)) | set(_tokens(e.category))
        toks.add(_norm(e.title))
        return toks

    def _score(self, query_terms: list[str], e: Entry) -> float:
        etoks = self._entry_tokens(e)
        best = 0.0
        for q in query_terms:
            # 1) direct substring / exact token match
            if any(q == t or q in t or t in q for t in etoks if t):
                best = max(best, 1.0)
                continue
            # 2) semantic relation
            rel = self._related.get(q, set())
            if rel & etoks or any(r in t for r in rel for t in etoks if len(r) > 2):
                best = max(best, 0.8)
                continue
            # 3) fuzzy (typos)
            for t in etoks:
                ratio = difflib.SequenceMatcher(None, q, t).ratio()
                if ratio >= 0.78:
                    best = max(best, 0.6 * ratio)
        return best

    def search(self, query: str, entries: list[Entry]) -> list[tuple[Entry, float]]:
        terms = [t for t in _tokens(query) if t not in _FILLER]
        if not terms:
            return [(e, 0.0) for e in entries]
        scored = [(e, self._score(terms, e)) for e in entries]
        hits = [(e, s) for e, s in scored if s > 0.0]
        hits.sort(key=lambda p: (-p[1], p[0].title.lower()))
        return hits
