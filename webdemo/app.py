"""VaultMind AI — interactive web demo (Streamlit).

A browser-clickable demonstration of the VaultMind feature set: encrypted
vault, semantic search, policy-aware generation, security audit, and breach
monitoring. Uses real AES-256-GCM (pure-Python core) so the cryptography is
genuine, not mocked.

IMPORTANT: this hosted demo is NOT the production security model. The real
application is a local desktop build (C++ core + Tkinter) where nothing
leaves the device. This page keeps each session's vault in memory only, per
browser session, and is meant to show behavior and UI — not to store real
credentials. See the banner in the app.

Run locally:   streamlit run webdemo/app.py
Deploy:        push to GitHub, then deploy on share.streamlit.io
"""
from __future__ import annotations

import difflib
import re
import time
import urllib.request
import urllib.error

import streamlit as st

import webcore as core

# ---------------------------------------------------------------- page config
st.set_page_config(page_title="VaultMind AI — Demo", page_icon="🛡",
                   layout="centered")

# ---------------------------------------------------------------- pink theme
st.markdown("""
<style>
  .stApp { background: #fdf2f6; }
  h1, h2, h3 { color: #6d2e46 !important; }
  .stButton>button {
     background:#b03060; color:white; border:none; border-radius:8px;
     font-weight:600; padding:0.45rem 1rem;
  }
  .stButton>button:hover { background:#d4587f; color:white; }
  .vm-card {
     background:#ffffff; border:1px solid #f3cfdf; border-radius:12px;
     padding:14px 16px; margin-bottom:10px;
  }
  .vm-muted { color:#a8788d; font-size:0.85rem; }
  .vm-banner {
     background:#fce9f0; border:1px solid #e3a9c4; border-radius:10px;
     padding:10px 14px; color:#6d2e46; font-size:0.85rem; margin-bottom:14px;
  }
  .vm-pill { border-radius:12px; padding:2px 10px; font-size:0.75rem;
             display:inline-block; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------- semantic map
SEMANTIC_MAP = {
    "google": {"gmail", "gsuite", "g-suite", "drive", "youtube", "gcloud"},
    "microsoft": {"outlook", "hotmail", "office", "onedrive", "teams", "azure"},
    "apple": {"icloud", "appstore", "itunes", "macos"},
    "amazon": {"aws", "prime", "kindle", "twitch"},
    "meta": {"facebook", "instagram", "whatsapp", "messenger"},
    "bank": {"banking", "chase", "wellsfargo", "citi", "credit", "finance"},
    "email": {"gmail", "outlook", "hotmail", "protonmail", "yahoo", "icloud"},
    "social": {"facebook", "instagram", "twitter", "x", "tiktok", "reddit",
               "linkedin", "discord"},
    "gaming": {"steam", "epic", "xbox", "playstation", "nintendo", "riot",
               "destiny", "bungie"},
    "streaming": {"netflix", "hulu", "spotify", "disney", "hbo", "max"},
    "school": {"canvas", "blackboard", "university", "unt", "student"},
}
_FILLER = {"my", "the", "a", "for", "all", "show", "me", "find", "get",
           "accounts", "account", "logins", "login", "passwords", "password"}


def build_related():
    rel = {}
    for concept, svcs in SEMANTIC_MAP.items():
        group = svcs | {concept}
        for tok in group:
            rel.setdefault(tok, set()).update(group - {tok})
    return rel


RELATED = build_related()


def tokens(text):
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def semantic_search(query, entries):
    terms = [t for t in tokens(query) if t not in _FILLER]
    if not terms:
        return entries
    scored = []
    for e in entries:
        etoks = set(tokens(e["title"])) | set(tokens(e["username"])) \
            | set(tokens(e["url"])) | set(tokens(e["category"]))
        best = 0.0
        for q in terms:
            if any(q == t or q in t or t in q for t in etoks if t):
                best = max(best, 1.0); continue
            rel = RELATED.get(q, set())
            if rel & etoks or any(r in t for r in rel for t in etoks if len(r) > 2):
                best = max(best, 0.8); continue
            for t in etoks:
                if difflib.SequenceMatcher(None, q, t).ratio() >= 0.78:
                    best = max(best, 0.6)
        if best > 0:
            scored.append((best, e))
    scored.sort(key=lambda p: -p[0])
    return [e for _s, e in scored]


# ---------------------------------------------------------------- breach check
def check_breach(password):
    digest = core.sha1_hex(password.encode())
    prefix, suffix = digest[:5], digest[5:]
    try:
        req = urllib.request.Request(
            "https://api.pwnedpasswords.com/range/" + prefix,
            headers={"User-Agent": "VaultMind-WebDemo", "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, str(exc)
    for line in body.splitlines():
        cand, _, count = line.partition(":")
        if cand.strip().upper() == suffix:
            try:
                return int(count.strip() or 0), None
            except ValueError:
                return 0, None
    return 0, None


def color(score):
    return "#2ea36b" if score >= 75 else "#e08a2e" if score >= 45 else "#c9314b"


# ---------------------------------------------------------------- session state
def init_state():
    if "vault_key" not in st.session_state:
        st.session_state.vault_key = None
    if "entries" not in st.session_state:
        st.session_state.entries = []      # list of plaintext dicts (in-memory)
    if "started" not in st.session_state:
        st.session_state.started = 0.0


def seed_demo():
    demo = [
        ("Gmail", "murphy@gmail.com", "Sunshine123", "gmail.com", "Email"),
        ("Google Drive", "murphy@gmail.com", "Sunshine123", "drive.google.com", "Work"),
        ("G-Suite Admin", "admin@team.com", "aaaa1111", "admin.google.com", "Work"),
        ("Steam", "murphy_gg", "P@ssw0rd!", "steampowered.com", "Gaming"),
        ("Chase Bank", "jmurphy", "correct-horse-battery-staple-99!", "chase.com", "Banking"),
        ("Netflix", "murphy@gmail.com", "netflix2021", "netflix.com", "Other"),
    ]
    return [dict(title=t, username=u, password=p, url=r, category=c,
                 modified=time.time()) for t, u, p, r, c in demo]


init_state()

# ---------------------------------------------------------------- banner
st.markdown('<div class="vm-banner">🔎 <b>Feature demo</b> — this hosted page '
            'demonstrates VaultMind\'s UI and features with real AES-256-GCM '
            'encryption. It is <b>not</b> the production security model: the '
            'real app is a local desktop build (C++ core + Tkinter) where '
            'nothing leaves your device. Don\'t enter real passwords here. '
            'Each browser session\'s vault lives in memory only.</div>',
            unsafe_allow_html=True)

st.title("🛡 VaultMind AI")
st.caption("Your Intelligent Security Co-Pilot — interactive demo")

# ---------------------------------------------------------------- unlock gate
if st.session_state.vault_key is None:
    st.subheader("Create your demo vault")
    st.write("Set a master password to unlock. (Demo only — use a throwaway.)")
    pw = st.text_input("Master password", type="password")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Unlock Vault", use_container_width=True):
            if len(pw) < 4:
                st.error("Use at least 4 characters for the demo.")
            else:
                salt = core.random_bytes(16)
                st.session_state.vault_key = core.derive_key(pw, salt)
                st.session_state.entries = seed_demo()
                st.session_state.started = time.time()
                st.rerun()
    with col2:
        st.button("Use Biometric / Face ID  (desktop only)",
                  use_container_width=True, disabled=True)
    st.stop()

# ---------------------------------------------------------------- main tabs
entries = st.session_state.entries
tabs = st.tabs(["🔍 Vault", "➕ Add", "⚡ Generator", "🛡 Security", "🌊 Breach"])

# ---- Vault + semantic search ----
with tabs[0]:
    st.subheader("My Vault")
    q = st.text_input("Search", placeholder='Try "my google accounts"')
    shown = semantic_search(q, entries) if q else sorted(
        entries, key=lambda e: e["title"].lower())
    if not shown:
        st.info("No semantic matches.")
    for e in shown:
        s = core.strength_score(e["password"])
        st.markdown(
            f'<div class="vm-card"><b>{e["title"]}</b> '
            f'<span style="color:{color(s)}">●</span><br>'
            f'<span class="vm-muted">{e["username"]} · {e["category"]} · '
            f'strength {s}/100</span></div>', unsafe_allow_html=True)

# ---- Add ----
with tabs[1]:
    st.subheader("Add Credential")
    t = st.text_input("Site name", key="add_title")
    u = st.text_input("Username / email", key="add_user")
    p = st.text_input("Password", key="add_pw")
    if p:
        s = core.strength_score(p)
        st.markdown(f'<span style="color:{color(s)}">Strength {s}/100 · '
                    f'{core.entropy_bits(p):.0f} bits</span>',
                    unsafe_allow_html=True)
    url = st.text_input("URL", key="add_url")
    cat = st.selectbox("Category",
                       ["Email", "Social", "Banking", "Work", "Gaming", "Other"])
    if st.button("Save Credential"):
        if not t:
            st.error("Site name is required.")
        else:
            entries.append(dict(title=t, username=u, password=p, url=url,
                                category=cat, modified=time.time()))
            st.success(f"Added {t}.")
            st.rerun()

# ---- Generator ----
with tabs[2]:
    st.subheader("AI Password Generator")
    length = st.slider("Length", 8, 64, 20)
    c1, c2, c3 = st.columns(3)
    up = c1.checkbox("A-Z", True)
    dg = c2.checkbox("0-9", True)
    sy = c3.checkbox("Symbols", True)
    colp1, colp2 = st.columns(2)
    maxlen = colp1.text_input("Site max length (optional)")
    allowed = colp2.text_input("Allowed symbols (optional)", placeholder="!@#_-")
    if st.button("⚡ Generate"):
        try:
            L = length
            if maxlen.strip().isdigit():
                L = min(L, int(maxlen.strip()))
            pw = core.generate_password(L, up, dg, sy,
                                        allowed.strip() or None)
            s = core.strength_score(pw)
            st.code(pw, language=None)
            st.markdown(f'<span style="color:{color(s)}">{core.entropy_bits(pw):.0f}'
                        f' bits · strength {s}/100</span>', unsafe_allow_html=True)
        except ValueError as exc:
            st.error(str(exc))

# ---- Security audit ----
with tabs[3]:
    st.subheader("Security Dashboard")
    if not entries:
        st.info("Vault is empty.")
    else:
        counts = {}
        for e in entries:
            counts[e["password"]] = counts.get(e["password"], 0) + 1
        scores = [core.strength_score(e["password"]) for e in entries]
        vault_score = max(0, min(100, int(sum(scores) / len(scores))))
        st.metric("Vault score", f"{vault_score}/100")

        weak = reused = common = 0
        rows = []
        for e in entries:
            s = core.strength_score(e["password"])
            issues = []
            if s < 60:
                issues.append("weak"); weak += 1
            if core.common_penalty(e["password"]) >= 0.5:
                issues.append("common password"); common += 1
            if counts[e["password"]] > 1:
                issues.append("reused"); reused += 1
            if issues:
                rows.append((e, s, issues))
        c1, c2, c3 = st.columns(3)
        c1.metric("Weak", weak); c2.metric("Reused", reused)
        c3.metric("Common", common)
        for e, s, issues in sorted(rows, key=lambda r: r[1]):
            st.markdown(
                f'<div class="vm-card"><b>{e["title"]}</b> '
                f'<span style="color:{color(s)}">{s}/100</span><br>'
                f'<span class="vm-muted">{" · ".join(issues)}</span></div>',
                unsafe_allow_html=True)
            if st.button(f"⚡ Suggest stronger password for {e['title']}",
                         key=f"fix_{e['title']}"):
                new = core.generate_password(20)
                e["password"] = new
                e["modified"] = time.time()
                st.success(f"{e['title']} updated to a "
                           f"{core.strength_score(new)}/100 password.")
                st.rerun()

# ---- Breach monitor ----
with tabs[4]:
    st.subheader("Breach Monitor")
    st.caption("Checks each password against HaveIBeenPwned using SHA-1 "
               "k-anonymity — only a 5-character hash prefix leaves the server.")
    if st.button("Run breach scan"):
        prog = st.progress(0.0)
        for i, e in enumerate(entries):
            count, err = check_breach(e["password"])
            if err:
                st.markdown(f'<div class="vm-card">◌ <b>{e["title"]}</b><br>'
                            f'<span class="vm-muted">check unavailable: {err}</span>'
                            f'</div>', unsafe_allow_html=True)
            elif count:
                st.markdown(f'<div class="vm-card">⚠ <b>{e["title"]}</b><br>'
                            f'<span style="color:#c9314b">seen in {count:,} '
                            f'breaches — change it</span></div>',
                            unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="vm-card">✓ <b>{e["title"]}</b><br>'
                            f'<span style="color:#2ea36b">not in known breaches'
                            f'</span></div>', unsafe_allow_html=True)
            prog.progress((i + 1) / len(entries))

# ---------------------------------------------------------------- footer
st.divider()
st.caption("VaultMind AI · Team Project 10 · web feature demo. "
           "Production build: local desktop app with C++ security core.")
