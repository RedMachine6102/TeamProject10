<<<<<<< HEAD
# VaultMind AI — Prototype Build (Phase 2, Group 10)

Intelligent password management prototype

Authors: Murphy Jacob, Gauri Kaushik, Shehtaz Mahboob, Colton Moore

| Layer | Language | Why |
|---|---|---|
| `core/vault_core.cpp` → `libvaultcore` | C++ (OpenSSL) | Security-critical, performance-sensitive: PBKDF2 key derivation, AES-256-GCM authenticated encryption, entropy/repetition/strength analysis, CSPRNG password generation, SHA-1 for k-anonymity |
| `vaultmind/` package | Python | Application logic: encrypted SQLite storage, auth & 15-minute sessions, semantic search, breach monitor, audit orchestration |
| `gui/app.py` | Python (Tkinter, stdlib) | Pink & white UI matching the Phase-2 mockups — zero pip dependencies |

## Requirements coverage

1. **Password audit engine** — `vaultmind/audit.py` sweeps the vault; entropy, repetition, and strength scoring run in C++ (`vc_entropy_bits`, `vc_repetition_ratio`, `vc_strength_score`). Flags weak / reused / old (180d+) passwords and attaches a ready-made replacement — the Security Dashboard's "⚡ One-click stronger password" button applies it.
2. **Natural-language semantic search** — `vaultmind/search.py`. Typing `google` (or `my google accounts`) surfaces Gmail, G-Suite, and Google Drive via a semantic knowledge map + filler-word stripping + fuzzy typo tolerance. The `search()` interface is designed so an embedding model can be swapped in later.
3. **Breach scan with k-anonymity** — `vaultmind/breach.py`. Passwords are SHA-1 hashed locally in C++; only the first **5 hex characters** are sent to the HaveIBeenPwned range API (with response padding enabled). Full hashes and passwords never leave the device.
4. **Policy-aware AI suggestions** — `vaultmind/generator.py` + `vc_generate_password`. Respects a site's **maximum length** and **permitted special characters**, uses rejection sampling (no modulo bias), and guarantees coverage of every enabled character class.
5. **15-minute sessions** — `vaultmind/auth.py`. Sessions hard-expire after 15 minutes; the GUI locks and requires **PIN** re-auth (the PIN wraps a copy of the vault key). Biometric unlock (Face ID / Windows Hello) is an OS-integration point noted in the UI; PIN stands in for it in this prototype.

## Security model

- Master password is **never stored** — login proves knowledge by decrypting a random verifier blob (AES-GCM authentication acts as the check).
- Vault key = PBKDF2-HMAC-SHA256(master password, 16-byte salt, 600k iterations).
- Every credential is an independent AES-256-GCM blob (`[12B IV][ciphertext][16B tag]`); SQLite never sees plaintext.
- Tampered ciphertext or a wrong key fails GCM authentication and is rejected.
- Generator clipboard copies auto-clear after 30 seconds.

## Build & run

```bash
# dependencies (Ubuntu/Debian)
sudo apt install g++ libssl-dev python3-tk

./build.sh          # compiles core/vault_core.cpp -> build/libvaultcore.so
python3 main.py     # launches the GUI
```

On first run you'll create a master password + PIN, and the vault is seeded with demo credentials (including deliberately weak/reused ones) so the audit, search, and breach screens have something to show. Delete `vault.db` to reset.

**Windows:** compile with MSVC/MinGW against OpenSSL to `build/vaultcore.dll` (the Python bindings already look for it). **macOS:** `brew install openssl`, output `libvaultcore.dylib`.

## Tests

```bash
python3 tests/test_prototype.py
```

31 headless checks covering the crypto core (round-trip, tamper rejection, SHA-1 vector), analysis, policy generation, storage/auth/session, semantic + fuzzy search, and the audit engine. The live HIBP check is skipped automatically when offline.

## Layout

```
vaultmind/
├── core/vault_core.cpp      C++ security engine
├── build.sh                 one-command build
├── vaultmind/
│   ├── corelib.py           ctypes bindings
│   ├── storage.py           encrypted SQLite vault
│   ├── auth.py              master pw / PIN / 15-min sessions
│   ├── search.py            NL semantic search
│   ├── audit.py             vault-wide audit engine
│   ├── generator.py         policy-aware generation
│   └── breach.py            HIBP k-anonymity client
├── gui/app.py               Tkinter UI (mockup-styled)
├── main.py                  launcher
└── tests/test_prototype.py  headless smoke tests
```

## Backlog hooks (from Trello plan)

Voice search can feed transcribed text straight into `SemanticSearch.search()`; phishing URL detection would slot into `storage.Entry.url` validation; gamification badges can key off `AuditReport.vault_score` history.
=======
# TeamProject10
Project 10 Group Repo for CSCE 3444
Team Lead - Murphy Jacob
Other roles TBD
>>>>>>> 407494ae41db4ea16d939e1c29e1b0e783260a07
