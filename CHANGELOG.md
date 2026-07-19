# Changelog

## 1.0.1 — Guided-upgrade browser fix

- **Fixed: guided password upgrade didn't reliably open the website.**
  The old code prepended `https://` and called `webbrowser.open`, which
  could silently no-op on Windows/WSL and would happily build a broken URL
  from a bare site name. Replaced with:
  - `_normalize_url` — trims whitespace, adds `https://` only when no scheme
    is present, preserves existing schemes and paths, and rejects values that
    aren't real web addresses (e.g. "Chase Bank") instead of opening a
    malformed URL.
  - `_open_in_default_browser` — uses the OS default browser with reliable
    per-platform fallbacks (`os.startfile` on Windows, `open` on macOS,
    `wslview`/`xdg-open` on Linux/WSL), and reports failure to the user with
    the address to open manually.
  - 11 new regression tests covering valid and rejected URL inputs.

## 1.0.0 — Production build (Sprint 1 defect resolution)

Addresses every defect and high/medium risk from the Group 10 test plan
(July 12, 2026).

### Defects fixed

- **D-001 (High) — one-click replacement out-of-sync / lockout.**
  Replaced the immediate overwrite with a guided, confirmation-based flow
  (`_staged_replace` in `gui/app.py`): copy the new password → open the site
  to change it → explicitly confirm success → only then save. The previous
  password is retained in per-entry rollback history (`Entry.push_history`),
  so a change can be undone. Covers BB-006.

- **D-002 (Medium) — corrupted rows silently skipped.**
  `VaultStorage.all()` now records every row that fails AES-GCM
  authentication in `last_integrity_failures` instead of dropping it quietly.
  The GUI shows an integrity warning with recovery guidance when the vault
  loads (`_warn_integrity_failures`). Covers BB-008 / WB-104.

- **D-003 (High) — Windows loaded the Linux `.so` (WinError 193).**
  `corelib.py` now selects the library for the *current* platform only
  (`vaultcore.dll` / `libvaultcore.dylib` / `libvaultcore.so`) and prints a
  clear build instruction when it's missing. Added `build.ps1` for Windows.
  Binaries are no longer committed (see D-004). Covers BB-009.

- **D-004 (Medium) — `.gitignore.txt` didn't work.**
  Added a real `.gitignore` covering build artifacts, databases, and
  bytecode, plus `scripts/fix_git_tracking.sh` to untrack files already
  committed under the old name.

### Risks mitigated

- **Risk 3 — strength score overrated common passwords.**
  New `vc_common_penalty` in the C++ core detects embedded dictionary words
  (`password`, `qwerty`, …), word-plus-trailing-digits patterns, and
  pure-digit passwords. Folded into `vc_strength_score`, so `password123`
  and `Sunshine123` now score ~5/100 instead of passing. The audit adds a
  "common password" issue label.

- **Risk 4 — offline PIN guessing on a copied database.**
  PIN key-derivation raised to 600,000 iterations and the limitation is now
  documented in `auth.py` with the production fix (OS-protected key storage:
  Windows Hello/DPAPI, macOS Keychain, libsecret).

### Testing

- Added `tests/test_vaultmind.py`: a pytest suite (33 cases) where every
  test runs independently and reports on its own, replacing the
  stop-on-first-failure smoke script (test plan §4.1).
- Breach-monitor network calls are **mocked**, so results no longer depend
  on internet access.
- New regression tests cover D-001 rollback, D-002 integrity reporting, and
  Risk 3 common-password detection.
- The original `tests/test_prototype.py` smoke suite is retained and still
  passes.
