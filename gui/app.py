"""VaultMind AI — Tkinter prototype GUI.
"""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from vaultmind import corelib                      # noqa: E402
from vaultmind.storage import VaultStorage, Entry  # noqa: E402
from vaultmind.auth import AuthManager, Session    # noqa: E402
from vaultmind.search import SemanticSearch        # noqa: E402
from vaultmind.audit import run_audit              # noqa: E402
from vaultmind.generator import PasswordPolicy, generate, analyze  # noqa: E402
from vaultmind import breach                       # noqa: E402

# ---- palette (pink & white) -------------------------------------
BG       = "#fdf2f6"   # app background — soft pink-white
CARD     = "#ffffff"   # card surface — white
CARD_HI  = "#fce4ee"   # input / hovered surface — light pink
ACCENT   = "#b03060"   # deep rose (primary buttons, headers)
ACCENT2  = "#d4587f"   # mid pink (links, secondary accents)
TEXT     = "#4a1e30"   # dark plum text
MUTED    = "#a8788d"   # muted mauve
GOOD     = "#2ea36b"   # strength: strong
WARN     = "#e08a2e"   # strength: fair
BAD      = "#c9314b"   # strength: weak / breach alerts

FONT      = ("Segoe UI", 11)
FONT_SM   = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 11, "bold")
FONT_H1   = ("Segoe UI", 18, "bold")
FONT_H2   = ("Segoe UI", 13, "bold")

CATEGORIES = ["All", "Email", "Social", "Banking", "Work", "Gaming", "Other"]


def strength_color(score: int) -> str:
    return GOOD if score >= 75 else WARN if score >= 45 else BAD


class VaultMindApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultMind AI")
        self.geometry("460x760")
        self.configure(bg=BG)
        self.resizable(False, False)

        self.store = VaultStorage()
        self.auth = AuthManager(self.store)
        self.searcher = SemanticSearch()
        self.session: Session | None = None
        self._screen: tk.Frame | None = None
        self._editing: Entry | None = None

        self.show_login()
        self.after(1000, self._tick)

    # session watchdog 
    def _tick(self):
        if self.session and self.session.expired:
            self.session.destroy()
            self.session = None
            messagebox.showinfo("Session expired",
                                "15-minute session ended.\nRe-authenticate with PIN or master password.")
            self.show_lock()
        self.after(1000, self._tick)

    # screen saver
    def _swap(self) -> tk.Frame:
        if self._screen is not None:
            self._screen.destroy()
        self._screen = tk.Frame(self, bg=BG)
        self._screen.pack(fill="both", expand=True, padx=18, pady=16)
        return self._screen

    def _btn(self, parent, text, cmd, primary=True, **kw):
        b = tk.Button(parent, text=text, command=cmd, relief="flat",
                      bg=ACCENT if primary else CARD_HI,
                      fg="white" if primary else TEXT,
                      activebackground=ACCENT2 if primary else CARD,
                      activeforeground="white", font=FONT_BOLD,
                      cursor="hand2", bd=0, padx=14, pady=8, **kw)
        return b

    def _entry(self, parent, show=None, placeholder=""):
        e = tk.Entry(parent, bg=CARD_HI, fg=TEXT, insertbackground=ACCENT,
                     relief="flat", font=FONT, show=show or "")
        if placeholder:
            e.insert(0, placeholder)
            e.config(fg=MUTED)
            def focus_in(_):
                if e.get() == placeholder:
                    e.delete(0, "end"); e.config(fg=TEXT, show=show or "")
            def focus_out(_):
                if not e.get():
                    e.config(show=""); e.insert(0, placeholder); e.config(fg=MUTED)
            e.bind("<FocusIn>", focus_in); e.bind("<FocusOut>", focus_out)
        return e

    def _header(self, parent, title, back=None):
        row = tk.Frame(parent, bg=BG); row.pack(fill="x", pady=(0, 12))
        if back:
            tk.Button(row, text="←", command=back, bg=BG, fg=ACCENT2, bd=0,
                      relief="flat", font=("Segoe UI", 14, "bold"),
                      activebackground=BG, activeforeground=ACCENT,
                      cursor="hand2").pack(side="left")
        tk.Label(row, text=title, bg=BG, fg=TEXT, font=FONT_H1).pack(side="left", padx=6)
        if self.session:
            self._timer_lbl = tk.Label(row, text="", bg=BG, fg=MUTED, font=FONT_SM)
            self._timer_lbl.pack(side="right")
            self._update_timer()

    def _update_timer(self):
        if self.session and not self.session.expired and hasattr(self, "_timer_lbl"):
            try:
                s = self.session.seconds_left
                self._timer_lbl.config(text=f"🔒 {s // 60}:{s % 60:02d}")
                self.after(1000, self._update_timer)
            except tk.TclError:
                pass

    # LOGIN / SETUP / PIN LOCK

    def show_login(self):
        f = self._swap()
        tk.Label(f, text="🛡", bg=BG, fg=ACCENT, font=("Segoe UI", 44)).pack(pady=(70, 4))
        tk.Label(f, text="VaultMind AI", bg=BG, fg=TEXT, font=("Segoe UI", 24, "bold")).pack()
        tk.Label(f, text="Intelligent Password Management", bg=BG, fg=MUTED,
                 font=FONT_SM).pack(pady=(0, 36))

        first_run = not self.store.initialized
        tk.Label(f, text="Create a master password" if first_run else "Master password",
                 bg=BG, fg=MUTED, font=FONT_SM, anchor="w").pack(fill="x", padx=30)
        pw = self._entry(f, show="•"); pw.pack(fill="x", padx=30, ipady=8, pady=(2, 12))

        pin = None
        if first_run:
            tk.Label(f, text="Choose a 4-6 digit PIN (quick unlock)", bg=BG, fg=MUTED,
                     font=FONT_SM, anchor="w").pack(fill="x", padx=30)
            pin = self._entry(f, show="•"); pin.pack(fill="x", padx=30, ipady=8, pady=(2, 12))

        def go():
            p = pw.get()
            if first_run:
                q = pin.get()
                if len(p) < 8:
                    messagebox.showwarning("Weak", "Master password must be 8+ characters."); return
                if not (q.isdigit() and 4 <= len(q) <= 6):
                    messagebox.showwarning("PIN", "PIN must be 4-6 digits."); return
                self.session = self.auth.initialize(p, q)
                self._seed_demo_data()
                self.show_vault()
            else:
                s = self.auth.login(p)
                if s is None:
                    messagebox.showerror("Denied", "Incorrect master password."); return
                self.session = s
                self.show_vault()

        self._btn(f, "Create Vault" if first_run else "Unlock Vault", go).pack(
            fill="x", padx=30, pady=(8, 6))
        if not first_run:
            self._btn(f, "Unlock with PIN  (biometric stand-in)",
                      self.show_lock, primary=False).pack(fill="x", padx=30)
        tk.Label(f, text="Biometric unlock (Face ID / Windows Hello) is an\n"
                         "OS integration point — PIN stands in for it here.",
                 bg=BG, fg=MUTED, font=FONT_SM, justify="center").pack(pady=18)
        pw.focus_set()

    def show_lock(self):
        f = self._swap()
        tk.Label(f, text="🔒", bg=BG, fg=ACCENT, font=("Segoe UI", 40)).pack(pady=(90, 6))
        tk.Label(f, text="Vault locked", bg=BG, fg=TEXT, font=FONT_H1).pack()
        tk.Label(f, text="Enter your PIN to resume", bg=BG, fg=MUTED, font=FONT_SM).pack(pady=(0, 26))
        pin = self._entry(f, show="•"); pin.pack(padx=120, fill="x", ipady=8)

        def go(_=None):
            s = self.auth.unlock_with_pin(pin.get())
            if s is None:
                messagebox.showerror("Denied", "Incorrect PIN."); return
            self.session = s
            self.show_vault()

        pin.bind("<Return>", go)
        self._btn(f, "Unlock", go).pack(pady=14, padx=120, fill="x")
        self._btn(f, "Use master password instead", self.show_login,
                  primary=False).pack(padx=120, fill="x")
        pin.focus_set()

    # VAULT HOMEPAGE  (semantic search + categories + list)

    def show_vault(self):
        f = self._swap()
        self._header(f, "My Vault")

        sf = tk.Frame(f, bg=CARD_HI); sf.pack(fill="x", pady=(0, 10))
        tk.Label(sf, text="🔍", bg=CARD_HI, fg=MUTED, font=FONT).pack(side="left", padx=(10, 0))
        q = self._entry(sf, placeholder="Try “my google accounts”")
        q.pack(side="left", fill="x", expand=True, ipady=8, padx=6)

        chips = tk.Frame(f, bg=BG); chips.pack(fill="x", pady=(0, 8))
        self._cat = tk.StringVar(value="All")
        for c in CATEGORIES:
            r = tk.Radiobutton(chips, text=c, value=c, variable=self._cat,
                               indicatoron=False, bg=CARD, fg=MUTED,
                               selectcolor=ACCENT, activebackground=CARD_HI,
                               activeforeground=TEXT, relief="flat", bd=0,
                               font=FONT_SM, padx=10, pady=4, cursor="hand2",
                               command=lambda: self._render_list(q))
            r.pack(side="left", padx=(0, 6))

        wrap = tk.Frame(f, bg=BG); wrap.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        self._list = tk.Frame(canvas, bg=BG)
        self._list.bind("<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self._list, anchor="nw", width=406)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        nav = tk.Frame(f, bg=BG); nav.pack(fill="x", pady=(10, 0))
        self._btn(nav, "＋ Add", lambda: self.show_editor(None)).pack(side="left", expand=True, fill="x", padx=(0, 4))
        self._btn(nav, "⚡ Generator", self.show_generator, primary=False).pack(side="left", expand=True, fill="x", padx=4)
        self._btn(nav, "🛡 Security", self.show_dashboard, primary=False).pack(side="left", expand=True, fill="x", padx=4)
        self._btn(nav, "🌊 Breach", self.show_breach, primary=False).pack(side="left", expand=True, fill="x", padx=(4, 0))

        q.bind("<KeyRelease>", lambda _e: self._render_list(q))
        self._render_list(q)

    def _render_list(self, qwidget):
        for w in self._list.winfo_children():
            w.destroy()
        try:
            entries = self.store.all(self.session.key)
        except PermissionError:
            return
        cat = self._cat.get()
        if cat != "All":
            entries = [e for e in entries if e.category == cat]

        query = qwidget.get().strip()
        if query and not query.startswith("Try “"):
            ranked = self.searcher.search(query, entries)
            entries = [e for e, _s in ranked]
            if not entries:
                tk.Label(self._list, text="No semantic matches.", bg=BG, fg=MUTED,
                         font=FONT).pack(pady=24)
        elif not entries:
            tk.Label(self._list, text="Vault is empty — add your first credential.",
                     bg=BG, fg=MUTED, font=FONT).pack(pady=24)

        for e in sorted(entries, key=lambda x: x.title.lower()) if not query else entries:
            score = corelib.strength_score(e.password)
            card = tk.Frame(self._list, bg=CARD, highlightbackground="#f3cfdf", highlightthickness=1); card.pack(fill="x", pady=4)
            dot = tk.Label(card, text="●", bg=CARD, fg=strength_color(score),
                           font=("Segoe UI", 14)); dot.pack(side="left", padx=(12, 8), pady=10)
            col = tk.Frame(card, bg=CARD); col.pack(side="left", fill="x", expand=True, pady=8)
            tk.Label(col, text=e.title, bg=CARD, fg=TEXT, font=FONT_BOLD,
                     anchor="w").pack(fill="x")
            tk.Label(col, text=f"{e.username}   ·   {e.category}", bg=CARD, fg=MUTED,
                     font=FONT_SM, anchor="w").pack(fill="x")
            tk.Button(card, text="Open", command=lambda ee=e: self.show_editor(ee),
                      bg=CARD_HI, fg=ACCENT2, bd=0, relief="flat", font=FONT_SM,
                      activebackground=CARD, activeforeground=ACCENT,
                      cursor="hand2", padx=10, pady=4).pack(side="right", padx=10)

    # ENTRY EDITOR

    def show_editor(self, entry: Entry | None):
        self._editing = entry
        f = self._swap()
        self._header(f, "Edit Credential" if entry else "New Credential",
                     back=self.show_vault)

        fields = {}
        for label, attr in [("Title", "title"), ("Username / Email", "username"),
                            ("Password", "password"), ("URL", "url")]:
            tk.Label(f, text=label, bg=BG, fg=MUTED, font=FONT_SM, anchor="w").pack(fill="x")
            w = self._entry(f); w.pack(fill="x", ipady=8, pady=(2, 10))
            if entry:
                w.insert(0, getattr(entry, attr))
            fields[attr] = w

        tk.Label(f, text="Category", bg=BG, fg=MUTED, font=FONT_SM, anchor="w").pack(fill="x")
        cat = tk.StringVar(value=entry.category if entry else "Other")
        om = tk.OptionMenu(f, cat, *CATEGORIES[1:])
        om.config(bg=CARD_HI, fg=TEXT, relief="flat", bd=0, font=FONT,
                  activebackground=CARD, highlightthickness=0)
        om["menu"].config(bg=CARD_HI, fg=TEXT, font=FONT)
        om.pack(fill="x", pady=(2, 10))

        meter = tk.Label(f, text="", bg=BG, font=FONT_SM, anchor="w")
        meter.pack(fill="x", pady=(0, 8))

        def refresh_meter(_=None):
            info = analyze(fields["password"].get())
            meter.config(fg=strength_color(info["score"]),
                         text=f"Strength {info['score']}/100 · "
                              f"{info['entropy_bits']:.0f} bits entropy")
        fields["password"].bind("<KeyRelease>", refresh_meter)
        refresh_meter()

        def suggest():
            fields["password"].delete(0, "end")
            fields["password"].insert(0, generate(PasswordPolicy()))
            refresh_meter()

        def save():
            title = fields["title"].get().strip()
            if not title:
                messagebox.showwarning("Missing", "Title is required."); return
            if entry:
                for a in ("title", "username", "password", "url"):
                    setattr(entry, a, fields[a].get())
                entry.category = cat.get()
                self.store.update(self.session.key, entry)
            else:
                self.store.add(self.session.key, Entry(
                    id=None, title=title, username=fields["username"].get(),
                    password=fields["password"].get(), url=fields["url"].get(),
                    category=cat.get()))
            self.show_vault()

        self._btn(f, "⚡ Suggest strong password", suggest, primary=False).pack(fill="x", pady=(0, 8))
        self._btn(f, "Save", save).pack(fill="x")
        if entry:
            def delete():
                if messagebox.askyesno("Delete", f"Delete “{entry.title}”?"):
                    self.store.delete(entry.id); self.show_vault()
            tk.Button(f, text="Delete credential", command=delete, bg=BG, fg=BAD,
                      bd=0, relief="flat", font=FONT_SM, activebackground=BG,
                      activeforeground=BAD, cursor="hand2").pack(pady=10)


    # AI GENERATOR

    def show_generator(self):
        f = self._swap()
        self._header(f, "AI Password Generator", back=self.show_vault)

        out_var = tk.StringVar()
        box = tk.Frame(f, bg=CARD, highlightbackground="#f3cfdf", highlightthickness=1); box.pack(fill="x", pady=(4, 10))
        out = tk.Entry(box, textvariable=out_var, bg=CARD, fg=ACCENT2,
                       relief="flat", font=("Consolas", 13), justify="center",
                       insertbackground=ACCENT)
        out.pack(fill="x", ipady=12, padx=8)

        meter = tk.Label(f, text="", bg=BG, font=FONT, anchor="center")
        meter.pack(fill="x", pady=(0, 12))

        tk.Label(f, text="Length", bg=BG, fg=MUTED, font=FONT_SM, anchor="w").pack(fill="x")
        length = tk.IntVar(value=20)
        tk.Scale(f, from_=8, to=64, orient="horizontal", variable=length,
                 bg=BG, fg=TEXT, troughcolor=CARD_HI, highlightthickness=0,
                 activebackground=ACCENT, font=FONT_SM).pack(fill="x", pady=(0, 8))

        upper = tk.BooleanVar(value=True); digits = tk.BooleanVar(value=True)
        syms = tk.BooleanVar(value=True)
        for text, var in [("Uppercase A-Z", upper), ("Digits 0-9", digits),
                          ("Symbols", syms)]:
            tk.Checkbutton(f, text=text, variable=var, bg=BG, fg=TEXT,
                           selectcolor=CARD_HI, activebackground=BG,
                           activeforeground=TEXT, font=FONT,
                           anchor="w").pack(fill="x")

        tk.Label(f, text="Site policy — max length / allowed specials (optional)",
                 bg=BG, fg=MUTED, font=FONT_SM, anchor="w").pack(fill="x", pady=(10, 0))
        row = tk.Frame(f, bg=BG); row.pack(fill="x", pady=(2, 12))
        maxlen = self._entry(row, placeholder="max len")
        maxlen.pack(side="left", ipady=6, fill="x", expand=True, padx=(0, 6))
        allowed = self._entry(row, placeholder="e.g. !@#_-")
        allowed.pack(side="left", ipady=6, fill="x", expand=True)

        def gen():
            try:
                ml = maxlen.get().strip()
                al = allowed.get().strip()
                policy = PasswordPolicy(
                    length=length.get(),
                    max_length=int(ml) if ml.isdigit() else None,
                    use_upper=upper.get(), use_digits=digits.get(),
                    use_symbols=syms.get(),
                    allowed_symbols=al if al and not al.startswith("e.g.") else None)
                pw = generate(policy)
            except ValueError as exc:
                messagebox.showerror("Policy conflict", str(exc)); return
            out_var.set(pw)
            info = analyze(pw)
            meter.config(fg=strength_color(info["score"]),
                         text=f"{info['entropy_bits']:.0f} bits · "
                              f"strength {info['score']}/100")

        def copy():
            self.clipboard_clear(); self.clipboard_append(out_var.get())
            self.after(30_000, self.clipboard_clear)   # auto-clear in 30 s
            messagebox.showinfo("Copied", "Copied. Clipboard clears in 30 s.")

        self._btn(f, "⚡ Generate", gen).pack(fill="x", pady=(4, 6))
        self._btn(f, "Copy to clipboard", copy, primary=False).pack(fill="x")
        gen()


    # SECURITY DASHBOARD  (audit engine)

    def show_dashboard(self):
        f = self._swap()
        self._header(f, "Security Dashboard", back=self.show_vault)

        entries = self.store.all(self.session.key)
        report = run_audit(entries)

        ring = tk.Canvas(f, width=150, height=150, bg=BG, highlightthickness=0)
        ring.pack(pady=(2, 4))
        ring.create_oval(12, 12, 138, 138, outline=CARD_HI, width=12)
        extent = -3.59 * report.vault_score
        ring.create_arc(12, 12, 138, 138, start=90, extent=extent, style="arc",
                        outline=strength_color(report.vault_score), width=12)
        ring.create_text(75, 68, text=str(report.vault_score),
                         fill=TEXT, font=("Segoe UI", 26, "bold"))
        ring.create_text(75, 96, text="vault score", fill=MUTED, font=FONT_SM)

        stats = tk.Frame(f, bg=BG); stats.pack(fill="x", pady=(0, 10))
        for label, n, color in [("Weak", report.weak, BAD),
                                ("Reused", report.reused, WARN),
                                ("Old (180d+)", report.old, WARN)]:
            cell = tk.Frame(stats, bg=CARD, highlightbackground="#f3cfdf", highlightthickness=1); cell.pack(side="left", expand=True,
                                                       fill="x", padx=3, ipady=8)
            tk.Label(cell, text=str(n), bg=CARD, fg=color, font=FONT_H2).pack()
            tk.Label(cell, text=label, bg=CARD, fg=MUTED, font=FONT_SM).pack()

        wrap = tk.Frame(f, bg=BG); wrap.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrap, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        lst = tk.Frame(canvas, bg=BG)
        lst.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=lst, anchor="nw", width=406)
        canvas.configure(yscrollcommand=sb.set)
        canvas.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")

        flagged = [x for x in report.findings if x.issues]
        if not flagged:
            tk.Label(lst, text="✓ Every password passed the audit.", bg=BG,
                     fg=GOOD, font=FONT).pack(pady=24)

        for fd in flagged:
            card = tk.Frame(lst, bg=CARD, highlightbackground="#f3cfdf", highlightthickness=1); card.pack(fill="x", pady=4)
            top = tk.Frame(card, bg=CARD); top.pack(fill="x", padx=12, pady=(8, 0))
            tk.Label(top, text=fd.entry.title, bg=CARD, fg=TEXT,
                     font=FONT_BOLD).pack(side="left")
            tk.Label(top, text=f"{fd.score}/100 · {fd.entropy:.0f} bits",
                     bg=CARD, fg=strength_color(fd.score), font=FONT_SM).pack(side="right")
            tk.Label(card, text=" · ".join(fd.issues), bg=CARD, fg=MUTED,
                     font=FONT_SM, anchor="w").pack(fill="x", padx=12)

            def fix(finding=fd):
                finding.entry.password = finding.suggestion
                self.store.update(self.session.key, finding.entry)
                messagebox.showinfo("Upgraded",
                                    f"“{finding.entry.title}” now has a "
                                    f"{corelib.strength_score(finding.entry.password)}/100 password.")
                self.show_dashboard()

            self._btn(card, "⚡ One-click stronger password", fix,
                      primary=False).pack(fill="x", padx=12, pady=8)


    # BREACH MONITOR  (HIBP k-anonymity)

    def show_breach(self):
        f = self._swap()
        self._header(f, "Breach Monitor", back=self.show_vault)
        tk.Label(f, text="Checks every vault password against HaveIBeenPwned\n"
                         "using SHA-1 k-anonymity — only a 5-character hash\n"
                         "prefix ever leaves this device.",
                 bg=BG, fg=MUTED, font=FONT_SM, justify="left").pack(fill="x", pady=(0, 10))

        results = tk.Frame(f, bg=BG); results.pack(fill="both", expand=True)
        status = tk.Label(f, text="", bg=BG, fg=MUTED, font=FONT_SM)
        status.pack(fill="x")

        def render(rows):
            for w in results.winfo_children():
                w.destroy()
            for title, res in rows:
                card = tk.Frame(results, bg=CARD, highlightbackground="#f3cfdf", highlightthickness=1); card.pack(fill="x", pady=4)
                if res.error:
                    icon, msg, color = "◌", res.error, MUTED
                elif res.breached:
                    icon, msg, color = "⚠", f"seen in {res.count:,} breaches — change it", BAD
                else:
                    icon, msg, color = "✓", "not found in known breaches", GOOD
                tk.Label(card, text=icon, bg=CARD, fg=color,
                         font=("Segoe UI", 14)).pack(side="left", padx=(12, 8), pady=10)
                col = tk.Frame(card, bg=CARD); col.pack(side="left", fill="x", expand=True, pady=8)
                tk.Label(col, text=title, bg=CARD, fg=TEXT, font=FONT_BOLD,
                         anchor="w").pack(fill="x")
                tk.Label(col, text=msg, bg=CARD, fg=color, font=FONT_SM,
                         anchor="w").pack(fill="x")

        def scan():
            entries = self.store.all(self.session.key)
            if not entries:
                status.config(text="Vault is empty."); return
            status.config(text="Scanning…")

            def work():
                rows = [(e.title, breach.check_password(e.password)) for e in entries]
                self.after(0, lambda: (render(rows), status.config(
                    text=f"Scanned {len(rows)} credentials.")))
            threading.Thread(target=work, daemon=True).start()

        self._btn(f, "Run breach scan", scan).pack(fill="x", pady=(0, 8))


    # demo seed data (first run only) — makes audit/search demoable instantly

    def _seed_demo_data(self):
        demo = [
            Entry(None, "Gmail", "johnsmith@gmail.com", "password123", "gmail.com", "Email"),
            Entry(None, "Google Drive", "johnsmith@gmail.com", "password123", "drive.google.com", "Work"),
            Entry(None, "G-Suite Admin", "admin@team.com", "aaaa1111", "admin.google.com", "Work"),
            Entry(None, "Steam", "john_smith", "P@ssw0rd!", "steampowered.com", "Gaming"),
            Entry(None, "Chase Bank", "jsmith", "correct-horse-battery-staple-99!", "chase.com", "Banking"),
            Entry(None, "Netflix", "johnsmith@gmail.com", "netflix2026", "netflix.com", "Other"),
        ]
        # age one entry so the "old password" audit path is visible
        demo[5].created = demo[5].modified = demo[5].created - 400 * 86400
        for e in demo:
            self.store.add(self.session.key, e)


def main():
    VaultMindApp().mainloop()


if __name__ == "__main__":
    main()
