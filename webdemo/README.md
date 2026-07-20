# VaultMind AI — Web Demo (deploy this to get a clickable link)

An interactive, browser-based demonstration of VaultMind's features. Real
AES-256-GCM encryption (pure-Python core), so the crypto is genuine — but
this is a **feature demo, not the production security model**. The real app
is the local desktop build (C++ core + Tkinter) where nothing leaves the
device. This page keeps each browser session's vault in memory only.

## Deploy to Streamlit Community Cloud (free, ~10 minutes → public URL)

You need: this `webdemo/` folder pushed to your GitHub repo, and a free
Streamlit Cloud account (sign in with GitHub).

1. **Push the demo to your repo.** From the repo root:
   ```powershell
   git add webdemo
   git commit -m "Add interactive web demo (Streamlit)"
   git push origin main
   ```

2. **Go to https://share.streamlit.io** and sign in with GitHub. Authorize it
   to see your repositories.

3. Click **Create app → Deploy a public app from GitHub** and fill in:
   - **Repository:** `RedMachine6102/TeamProject10`
   - **Branch:** `main`
   - **Main file path:** `webdemo/app.py`
   - (Advanced settings → Python version 3.11+ is fine.)

4. Click **Deploy**. First build takes 2–5 minutes while it installs
   `streamlit` and `cryptography` from `webdemo/requirements.txt`.

5. You get a public URL like
   `https://teamproject10-xxxx.streamlit.app` — **that's the link you
   submit.** Anyone can click it and use the app in their browser.

## Run it locally first (optional sanity check)

```bash
pip install -r webdemo/requirements.txt
streamlit run webdemo/app.py
# opens http://localhost:8501
```

## What the grader can do in the browser

- Unlock a demo vault with a master password (real PBKDF2 key derivation).
- **Semantic search** — type "my google accounts", get Gmail/Drive/G-Suite.
- **Add** a credential with a live strength meter.
- **Generator** — policy-aware password generation (length cap, allowed symbols).
- **Security dashboard** — vault score; weak/reused/common-password flags with
  one-click stronger replacements.
- **Breach monitor** — live HaveIBeenPwned k-anonymity check.

## Important framing for your submission

State plainly that this is a hosted UI/feature demo. The production build is
the desktop application in the repo root, whose security model (local-only,
zero-knowledge, C++ core) is the actual deliverable. The web version exists
so the application is clickable in a browser as required; it deliberately
does not persist data server-side. Don't enter real passwords into it.

## Deploy notes / troubleshooting

- If the build fails on `cryptography`, Streamlit Cloud occasionally needs a
  moment; hit **Reboot app**. The wheels are prebuilt for their Linux image,
  so no compiler is required (unlike the C++ desktop core — which is exactly
  why the web demo uses a pure-Python core).
- The app has no database and writes nothing to disk; each session is
  independent. Refreshing the page resets the demo vault.
