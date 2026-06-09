import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import os
from datetime import datetime
from auditor_core import AuditorCore
from export_report import save_report, FORMATS

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")

BG = "#0D1117"
BG2 = "#161B22"
BG3 = "#1C2128"
FG = "#E6EDF3"
FG2 = "#8B949E"
ACCENT = "#58A6FF"
GREEN = "#3FB950"
RED = "#F85149"
AMBER = "#D29922"
GRAY = "#8B949E"
BORDER = "#30363D"
SCROLL = "#484F58"
SCROLL_HOVER = "#58A6FF"
SELECT_BG = "#1F3A5F"
SELECT_FG = "#FFFFFF"
ROW_ALT = "#11181C"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")
FONT_BADGE = ("Segoe UI", 9, "bold")

STATUS_COLORS = {"PASS": GREEN, "FAIL": RED, "WARNING": AMBER, "PENDING": GRAY}

FORMAT_NAMES = list(FORMATS.keys())

class CISOAuditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CISO Security Auditor")
        self.root.minsize(1024, 700)
        self.root.configure(bg=BG)
        self.root.state("zoomed")

        self.auditor = AuditorCore()
        self.scan_complete = False
        self.selected_check = None
        self.export_format = tk.StringVar(value="html")

        self._build_ui()
        self._bind_events()
        self._load_settings()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_settings(self):
        try:
            with open(SETTINGS_FILE, "r") as f:
                s = json.load(f)
            self.export_format.set(s.get("format", "html"))
        except:
            pass

    def _save_settings(self):
        try:
            s = {
                "format": self.export_format.get(),
            }
            with open(SETTINGS_FILE, "w") as f:
                json.dump(s, f, indent=2)
        except:
            pass

    def _on_close(self):
        self._save_settings()
        self.root.destroy()

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        # ========== ROW 0: Header ==========
        header = tk.Frame(self.root, bg=BG2, height=56, highlightthickness=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)

        tk.Label(header, text="CISO WINDOWS SECURITY AUDITOR", bg=BG2, fg=ACCENT,
                 font=FONT_TITLE).pack(side=tk.LEFT, padx=25, pady=14)

        score_frame = tk.Frame(header, bg=BG2)
        score_frame.pack(side=tk.RIGHT, padx=25, pady=14)

        self.header_trend = tk.Label(score_frame, text="", bg=BG2, fg=GRAY,
                                     font=FONT_MONO)
        self.header_trend.pack(side=tk.LEFT, padx=(0, 12))

        self.header_score = tk.Label(score_frame, text="SCORE: --", bg=BG2, fg=GRAY,
                                     font=FONT_MONO_BOLD)
        self.header_score.pack(side=tk.LEFT)

        # ========== ROW 1: Toolbar ==========
        toolbar = tk.Frame(self.root, bg=BG, highlightthickness=0)
        toolbar.grid(row=1, column=0, sticky="ew", padx=20, pady=(16, 4))
        toolbar.columnconfigure(1, weight=1)

        self.run_btn = tk.Button(toolbar, text="RUN SCAN", bg=ACCENT, fg="#FFF",
                                 font=FONT_BOLD, command=self.run_scan_thread,
                                 relief=tk.FLAT, padx=20, pady=6, cursor="hand2",
                                 activebackground="#4B91E0", activeforeground="#FFF",
                                 borderwidth=0)
        self.run_btn.grid(row=0, column=0, padx=(0, 8), sticky="w")

        # --- Search bar ---
        search_frame = tk.Frame(toolbar, bg=BG3, highlightthickness=1, highlightbackground=BORDER)
        search_frame.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        search_frame.columnconfigure(1, weight=1)

        tk.Label(search_frame, text="🔍", bg=BG3, fg=FG2, font=FONT).grid(row=0, column=0, padx=(8, 0))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._filter_tree())
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                     bg=BG3, fg=FG, insertbackground=FG, font=FONT,
                                     highlightthickness=0, bd=0)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(4, 4), pady=4)
        self.search_clear = tk.Button(search_frame, text="✕", bg=BG3, fg=FG2, font=FONT,
                                      command=lambda: self.search_var.set(""),
                                      relief=tk.FLAT, cursor="hand2", width=2, bd=0)
        self.search_clear.grid(row=0, column=2, padx=(0, 6))

        # Right-side toolbar cluster
        right_frame = tk.Frame(toolbar, bg=BG)
        right_frame.grid(row=0, column=2, sticky="e")

        self.export_btn = tk.Button(right_frame, text="EXPORT", bg=BG3, fg=ACCENT,
                                    font=FONT_BOLD, command=self.export_report,
                                    relief=tk.FLAT, padx=20, pady=6, cursor="hand2",
                                    activebackground=BORDER, activeforeground=ACCENT,
                                    borderwidth=1, highlightbackground=BORDER,
                                    state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Separator(right_frame, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=6, pady=4)

        fmt_lbl = tk.Label(right_frame, text="Format:", bg=BG, fg=FG2, font=FONT)
        fmt_lbl.pack(side=tk.LEFT, padx=(0, 4))

        self._fmt_btns = []
        for fmt in FORMAT_NAMES:
            rb = tk.Radiobutton(right_frame, text=FORMATS[fmt]["desc"], variable=self.export_format,
                                value=fmt, bg=BG, fg=FG2, selectcolor=BG3,
                                font=FONT, activebackground=BG, activeforeground=ACCENT,
                                highlightthickness=0, bd=0, cursor="hand2")
            rb.pack(side=tk.LEFT, padx=(0, 8))
            self._fmt_btns.append(rb)

        self.fix_all_btn = tk.Button(right_frame, text="FIX ALL", bg=BG3, fg=AMBER,
                                     font=FONT_BOLD, command=self.fix_all_auto_fixable,
                                     relief=tk.FLAT, padx=16, pady=6, cursor="hand2",
                                     activebackground=BORDER, activeforeground=AMBER,
                                     borderwidth=1, highlightbackground=BORDER,
                                     state=tk.DISABLED)
        self.fix_all_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.undo_btn = tk.Button(right_frame, text="UNDO", bg=BG3, fg=RED,
                                  font=FONT_BOLD, command=self.undo_all_fixes,
                                  relief=tk.FLAT, padx=14, pady=6, cursor="hand2",
                                  activebackground=BORDER, activeforeground=RED,
                                  borderwidth=1, highlightbackground=BORDER,
                                  state=tk.DISABLED)
        self.undo_btn.pack(side=tk.LEFT, padx=(6, 0))

        ttk.Separator(right_frame, orient="vertical").pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=4)

        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(right_frame, variable=self.progress_var,
                                        maximum=100, length=200, mode="determinate")
        self.progress.pack(side=tk.LEFT, padx=(0, 8))

        self.status_lbl = tk.Label(right_frame, text="Ready to scan", bg=BG, fg=FG2,
                                   font=FONT)
        self.status_lbl.pack(side=tk.LEFT)

        # ========== ROW 2: Summary bar ==========
        summary = tk.Frame(self.root, bg=BG2, highlightthickness=1,
                           highlightbackground=BORDER)
        summary.grid(row=2, column=0, sticky="ew", padx=20, pady=(8, 4))

        self._score_labels = {}
        labels = [("PASS", GREEN), ("FAIL", RED), ("WARN", AMBER), ("PENDING", GRAY)]
        row_f = tk.Frame(summary, bg=BG2)
        row_f.pack(pady=6, padx=14)

        for i, (name, color) in enumerate(labels):
            if i > 0:
                tk.Frame(row_f, bg=BORDER, width=1, height=20).pack(side=tk.LEFT, padx=12)
            lbl = tk.Label(row_f, text=f"{name}: --", bg=BG2, fg=color,
                           font=FONT_MONO_BOLD)
            lbl.pack(side=tk.LEFT)
            self._score_labels[name.lower()] = lbl

        # ========== ROW 3: Main content (history + treeview + detail pane) ==========
        main = tk.Frame(self.root, bg=BG, highlightthickness=0)
        main.grid(row=3, column=0, sticky="nsew", padx=20, pady=(4, 16))
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)
        main.rowconfigure(1, weight=0)

        # --- History panel (left side) ---
        history_outer = tk.Frame(main, bg=BG3, highlightthickness=1,
                                 highlightbackground=BORDER, width=220)
        history_outer.grid(row=0, column=0, sticky="ns", pady=(0, 8))
        history_outer.grid_propagate(False)

        history_top = tk.Frame(history_outer, bg=BG2, height=30)
        history_top.pack(fill=tk.X)
        history_top.pack_propagate(False)
        tk.Label(history_top, text="SCAN HISTORY", bg=BG2, fg=ACCENT,
                 font=FONT_BOLD).pack(side=tk.LEFT, padx=10, pady=5)

        history_scroll = tk.Frame(history_outer, bg=BG3)
        history_scroll.pack(fill=tk.BOTH, expand=True)
        history_scroll.rowconfigure(0, weight=1)
        history_scroll.columnconfigure(0, weight=1)

        self.history_list = tk.Frame(history_scroll, bg=BG3)
        self.history_list.grid(row=0, column=0, sticky="nsew")

        vsb_h = tk.Scrollbar(history_scroll, orient="vertical", command=self.history_list.yview)
        vsb_h.grid(row=0, column=1, sticky="ns")
        self.history_list.configure(yscrollcommand=vsb_h.set)

        self.history_canvas = tk.Canvas(history_scroll, bg=BG3, highlightthickness=0)
        self.history_canvas.grid(row=0, column=0, sticky="nsew")
        self.history_canvas.create_window((0, 0), window=self.history_list, anchor="nw")
        self.history_canvas.configure(yscrollcommand=vsb_h.set)
        self.history_list.bind("<Configure>", lambda e: self.history_canvas.configure(
            scrollregion=self.history_canvas.bbox("all")))

        self._history_items = []
        self._load_history_panel()

        # --- Treeview container ---
        tree_outer = tk.Frame(main, bg=BG3, highlightthickness=1,
                              highlightbackground=BORDER)
        tree_outer.grid(row=0, column=1, sticky="nsew", pady=(0, 8), padx=(8, 0))
        tree_outer.rowconfigure(2, weight=1)
        tree_outer.columnconfigure(0, weight=1)

        # Treeview toolbar (column headers + count)
        tree_top = tk.Frame(tree_outer, bg=BG2, height=30)
        tree_top.grid(row=0, column=0, sticky="ew")
        tree_top.grid_propagate(False)

        tk.Label(tree_top, text="SECURITY CHECKS", bg=BG2, fg=ACCENT,
                 font=FONT_BOLD).pack(side=tk.LEFT, padx=12, pady=5)
        self.row_count_lbl = tk.Label(tree_top, text="100 items", bg=BG2, fg=FG2,
                                       font=FONT)
        self.row_count_lbl.pack(side=tk.RIGHT, padx=12, pady=5)

        # --- Category toggle bar ---
        self._cat_bar = tk.Frame(tree_outer, bg=BG2, highlightthickness=1, highlightbackground=BORDER)
        self._cat_bar.grid(row=1, column=0, sticky="ew")
        self._cat_btns = {}
        self._collapsed_cats = set()
        FONT_CAT = ("Segoe UI", 8)
        for cat in self.auditor.CATEGORIES:
            short = cat.split(",")[0].split(" &")[0][:12]
            btn = tk.Button(self._cat_bar, text=f"▾ {short}", bg=BG2, fg=FG2,
                           font=FONT_CAT, relief=tk.FLAT, padx=6, pady=2, cursor="hand2",
                           activebackground=BG3, activeforeground=ACCENT, bd=0)
            btn.pack(side=tk.LEFT, padx=2, pady=2)
            btn.bind("<Button-1>", lambda e, c=cat: self._toggle_category(c))
            self._cat_btns[cat] = btn

        # Treeview + scrollbar
        tree_frame = tk.Frame(tree_outer, bg=BG)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        scroll_style = {"bg": BG2, "troughcolor": BG, "activebackground": SCROLL_HOVER,
                         "highlightbackground": BORDER, "width": 14, "borderwidth": 0}
        vsb = tk.Scrollbar(tree_frame, orient="vertical", **scroll_style)
        vsb.grid(row=0, column=1, sticky="ns")

        hsb = tk.Scrollbar(tree_frame, orient="horizontal", **scroll_style)
        hsb.grid(row=1, column=0, sticky="ew")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background=BG, foreground=FG,
                        fieldbackground=BG, font=FONT_MONO, rowheight=30)
        style.map("Treeview", background=[("selected", SELECT_BG)],
                  foreground=[("selected", SELECT_FG)])
        style.configure("Treeview.Heading", background=BG2, foreground=ACCENT,
                        font=FONT_MONO_BOLD, relief="flat")
        style.map("Treeview.Heading", background=[("active", BG3)])

        columns = ("ID", "Category", "Check Name", "Status", "Details")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                                 yscrollcommand=vsb.set, xscrollcommand=hsb.set,
                                 style="Treeview", selectmode="browse")
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        self.tree.heading("ID", text="ID")
        self.tree.column("ID", width=50, minwidth=40, anchor=tk.CENTER, stretch=False)

        self.tree.heading("Category", text="Domain")
        self.tree.column("Category", width=140, minwidth=120, stretch=True)

        self.tree.heading("Check Name", text="Security Check")
        self.tree.column("Check Name", width=280, minwidth=200, stretch=True)

        self.tree.heading("Status", text="Status")
        self.tree.column("Status", width=80, minwidth=70, anchor=tk.CENTER, stretch=False)

        self.tree.heading("Details", text="Findings")
        self.tree.column("Details", width=400, minwidth=200, stretch=True)

        self.tree.grid(row=0, column=0, sticky="nsew")

        self.tree.tag_configure("PASS", foreground=GREEN, background=BG)
        self.tree.tag_configure("FAIL", foreground=RED, background=BG)
        self.tree.tag_configure("WARNING", foreground=AMBER, background=BG)
        self.tree.tag_configure("PENDING", foreground=GRAY, background=BG)
        self.tree.tag_configure("alt", background=ROW_ALT)

        self._col_weights = {"Category": 2, "Check Name": 4, "Details": 6}
        self._col_fixed = {"ID": 50, "Status": 80}
        self.tree.bind("<Configure>", self._on_tree_configure)
        self.tree.bind("<Map>", self._on_tree_configure)

        # --- Detail pane ---
        self.detail_outer = tk.Frame(main, bg=BG3, highlightthickness=1,
                                     highlightbackground=BORDER)
        self.detail_outer.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        self.detail_outer.columnconfigure(0, weight=1)

        # Empty state
        self.detail_empty = tk.Frame(self.detail_outer, bg=BG3, height=40)
        self.detail_empty.grid(row=0, column=0, sticky="ew")

        tk.Label(self.detail_empty, text="Click a row to see what's wrong and how to fix it",
                 bg=BG3, fg=FG2, font=FONT).pack(pady=8)

        # Active detail (hidden by default)
        self.detail_active = tk.Frame(self.detail_outer, bg=BG3)
        self.detail_active.grid(row=1, column=0, sticky="ew", padx=16, pady=(4, 10))
        self.detail_active.columnconfigure(1, weight=1)
        self.detail_active.bind("<Configure>", self._update_wraplength)

        # Row 0: Title + Status badge
        self.detail_title = tk.Label(self.detail_active, text="", bg=BG3, fg=ACCENT,
                                     font=FONT_BOLD)
        self.detail_title.grid(row=0, column=0, sticky="w")

        self.detail_badge = tk.Label(self.detail_active, text="", bg=GRAY, fg="#FFF",
                                     font=FONT_BADGE, padx=8, pady=2)
        self.detail_badge.grid(row=0, column=1, sticky="w", padx=(8, 0))

        # Row 1: Details heading
        tk.Label(self.detail_active, text="Details:", bg=BG3, fg=FG2,
                 font=FONT_BOLD).grid(row=1, column=0, sticky="w", pady=(6, 2))
        self.detail_text = tk.Label(self.detail_active, text="", bg=BG3, fg=FG,
                                    font=FONT, wraplength=800, justify=tk.LEFT)
        # Row 2: Remediation line
        remed_row = tk.Frame(self.detail_active, bg=BG3)
        remed_row.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        remed_row.columnconfigure(1, weight=1)

        tk.Label(remed_row, text="Remediation:", bg=BG3, fg=AMBER,
                 font=FONT_BOLD).grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.detail_remediation = tk.Label(remed_row, text="", bg=BG3, fg=AMBER,
                                           font=FONT, wraplength=800, justify=tk.LEFT)
        self.detail_remediation.grid(row=0, column=1, sticky="w")

        # Row 3: Fix button + result
        fix_row = tk.Frame(self.detail_active, bg=BG3)
        fix_row.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        self.fix_btn = tk.Button(fix_row, text="FIX THIS", bg=RED, fg="#FFF",
                                 font=FONT_BOLD, command=self.apply_fix,
                                 relief=tk.FLAT, padx=18, pady=4, cursor="hand2",
                                 activebackground="#CF3A4A", activeforeground="#FFF",
                                 borderwidth=0, state=tk.DISABLED)
        self.fix_btn.pack(side=tk.LEFT)

        self.undo_single_btn = tk.Button(fix_row, text="UNDO FIX", bg=BG3, fg=RED,
                                         font=FONT_BOLD, command=self._undo_from_detail,
                                         relief=tk.FLAT, padx=14, pady=4, cursor="hand2",
                                         activebackground=BORDER, activeforeground=RED,
                                         borderwidth=1, highlightbackground=BORDER,
                                         state=tk.DISABLED)
        self.undo_single_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.fix_result_lbl = tk.Label(fix_row, text="", bg=BG3, font=FONT)
        self.fix_result_lbl.pack(side=tk.LEFT, padx=(12, 0))

        # Initially hide active detail
        self.detail_active.grid_remove()

        # ========== Bottom padding ==========
        self.root.bind("<Configure>", self._on_root_configure)
        self.root.after(100, self._resize_all)
        self._populate_initial()

    def _bind_events(self):
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<KP_Enter>", lambda e: self.apply_fix())
        self.tree.bind("<Return>", lambda e: self.apply_fix())

    def _load_history_panel(self):
        for item in self.history_list.winfo_children():
            item.destroy()
        self._history_items = []
        history = self.auditor.load_history()
        if not history:
            lbl = tk.Label(self.history_list, text="No scans yet", bg=BG3, fg=FG2,
                           font=FONT, wraplength=180)
            lbl.pack(pady=20, padx=10)
            return
        for i, scan in enumerate(reversed(history)):
            ts = scan.get("timestamp", "")
            score = scan.get("score", 0)
            try:
                dt = datetime.fromisoformat(ts)
                time_str = dt.strftime("%b %d, %H:%M")
            except:
                time_str = ts[:16]
            score_color = GREEN if score >= 70 else (AMBER if score >= 40 else RED)
            item = tk.Frame(self.history_list, bg=BG3, cursor="hand2")
            item.pack(fill=tk.X, padx=6, pady=2)
            tk.Label(item, text=time_str, bg=BG3, fg=FG2, font=FONT,
                     anchor="w").pack(fill=tk.X, padx=8)
            tk.Label(item, text=f"{score}%", bg=BG3, fg=score_color,
                     font=FONT_MONO_BOLD, anchor="w").pack(fill=tk.X, padx=8)
            self._history_items.append((item, scan))

    def _filter_tree(self, *_):
        q = self.search_var.get().lower()
        for item in self.tree.get_children():
            cid = int(item)
            check = next((c for c in self.auditor.checks if c.id == cid), None)
            if not check:
                continue
            cat_collapsed = check.category in self._collapsed_cats
            vals = [str(v).lower() for v in self.tree.item(item, "values")]
            text_match = not q or any(q in v for v in vals)
            if text_match and not cat_collapsed:
                self.tree.reattach(item, "", "end")
            else:
                self.tree.detach(item)
        shown = len(self.tree.get_children())
        self.row_count_lbl.config(text=f"{shown} items")

    def _toggle_category(self, cat):
        if cat in self._collapsed_cats:
            self._collapsed_cats.discard(cat)
        else:
            self._collapsed_cats.add(cat)
        btn = self._cat_btns[cat]
        collapsed = cat in self._collapsed_cats
        short = cat.split(",")[0].split(" &")[0][:12]
        btn.config(text=f"{'▸' if collapsed else '▾'} {short}",
                   fg=RED if collapsed else FG2)
        self._filter_tree()

    def _on_right_click(self, event):
        sel = self.tree.identify_row(event.y)
        if not sel:
            return
        self.tree.selection_set(sel)
        cid = int(sel)
        check = next((c for c in self.auditor.checks if c.id == cid), None)
        if not check:
            return
        menu = tk.Menu(self.root, tearoff=0, bg=BG2, fg=FG, activebackground=SELECT_BG,
                       activeforeground=FG, font=FONT, relief=tk.FLAT, bd=1)
        menu.add_command(label="View Details", command=lambda: self._on_select(None))
        if check.auto_fixable and check.status in ("FAIL", "WARNING"):
            menu.add_separator()
            menu.add_command(label="Apply Auto-Fix", command=self.apply_fix)
        if check.id in [cid for cid, _ in self.auditor.fix_history]:
            menu.add_separator()
            menu.add_command(label="Undo This Fix", command=lambda: self._undo_single(check.id))
        menu.add_separator()
        menu.add_command(label="Copy Check ID", command=lambda: self._copy_text(f"#{check.id:03d}"))
        menu.add_command(label="Copy Details", command=lambda: self._copy_text(check.details))
        menu.post(event.x_root, event.y_root)

    def _copy_text(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _undo_single(self, check_id):
        if not self.auditor.is_admin():
            messagebox.showwarning("Need Admin",
                "Run as Administrator to fix things.")
            return
        check = next((c for c in self.auditor.checks if c.id == check_id), None)
        if not check:
            return
        ok = messagebox.askyesno(
            "Undo this fix?",
            f"Revert #{check_id:03d}?\n\n{check.name}\n\n"
            "I'll restore the registry key to its original value.")
        if not ok:
            return

        def do_undo():
            result = self.auditor.undo_fix(check_id)
            try:
                self.root.after(0, lambda: self._single_undo_complete(check_id, result))
            except:
                pass

        t = threading.Thread(target=do_undo, daemon=True)
        t.start()

    def _single_undo_complete(self, check_id, result):
        check = next((c for c in self.auditor.checks if c.id == check_id), None)
        if check:
            self.tree.set(check.id, "Status", check.status)
            self.tree.set(check.id, "Details", check.details)
            alt = (check.id % 2 == 0)
            self.tree.item(check.id, tags=(check.status, "alt") if alt else (check.status,))
        self._update_summary()
        if self.selected_check and self.selected_check.id == check_id:
            self._show_detail(self.selected_check)
        self.status_lbl.config(text=result)
        if not self.auditor.fix_history:
            self.undo_btn.config(state=tk.DISABLED)

    def _undo_from_detail(self):
        if self.selected_check:
            self._undo_single(self.selected_check.id)

    def _resize_all(self):
        self._on_tree_configure(None)
        self._update_wraplength()

    def _on_tree_configure(self, event):
        if event and event.widget != self.tree and self.tree.winfo_width() < 100:
            return
        total_w = self.tree.winfo_width()
        if total_w < 100:
            total_w = 600
        fixed_sum = sum(self._col_fixed.values())
        avail = total_w - fixed_sum - 10
        total_weight = sum(self._col_weights.values()) or 1
        for col, weight in self._col_weights.items():
            w = max(int(avail * weight / total_weight), self.tree.column(col, "minwidth"))
            self.tree.column(col, width=w)

    def _update_wraplength(self, event=None):
        w = self.detail_outer.winfo_width() - 50
        if w < 200:
            w = 200
        self.detail_text.config(wraplength=w)
        self.detail_remediation.config(wraplength=w)

    def _on_root_configure(self, event):
        if event.widget == self.root:
            self.root.after_idle(self._resize_all)

    def _show_detail(self, check):
        self.detail_empty.grid_remove()
        self.detail_active.grid()

        color = STATUS_COLORS.get(check.status, GRAY)
        self.detail_title.config(text=f"#{check.id:03d}  {check.name}")
        self.detail_badge.config(text=f" {check.status} ", bg=color)
        self.detail_text.config(text=check.details)

        if check.remediation:
            icon = "⚡" if check.auto_fixable else "📝"
            self.detail_remediation.config(text=f"{icon}  {check.remediation}")
        else:
            self.detail_remediation.config(text="")

        if check.auto_fixable:
            self.fix_btn.config(state=tk.NORMAL, text="FIX THIS", bg=RED,
                                activebackground="#CF3A4A")
        else:
            self.fix_btn.config(state=tk.DISABLED, text="MANUAL FIX ONLY", bg=GRAY,
                                activebackground=GRAY)
        has_been_fixed = check.id in [cid for cid, _ in self.auditor.fix_history]
        self.undo_single_btn.config(state=tk.NORMAL if has_been_fixed else tk.DISABLED)
        self.fix_result_lbl.config(text="")

    def _hide_detail(self):
        self.detail_active.grid_remove()
        self.detail_empty.grid()

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            self.selected_check = None
            self._hide_detail()
            return
        cid = int(sel[0])
        check = next((c for c in self.auditor.checks if c.id == cid), None)
        if not check:
            return
        self.selected_check = check
        self._show_detail(check)

    def apply_fix(self):
        if not self.selected_check or not self.selected_check.auto_fixable:
            return
        if not self.auditor.is_admin():
            self.fix_result_lbl.config(
                text="Can't fix without admin. Right-click the app and 'Run as Administrator'.",
                fg=RED)
            return
        check = self.selected_check
        ok = messagebox.askyesno(
            "Fix this?",
            f"Fix #{check.id:03d}?\n\n"
            f"{check.name}\n\n"
            "I'll create a restore point first so you can undo.")
        if not ok:
            return

        def do_fix():
            try:
                result = self.auditor.fix_check(self.selected_check)
                self.root.after(0, lambda: self._fix_complete(result))
            except Exception as e:
                try:
                    self.root.after(0, lambda: self.fix_result_lbl.config(
                        text=f"Error: {str(e)}", fg=RED))
                except:
                    pass

        self.fix_btn.config(state=tk.DISABLED, text="FIXING...", fg=AMBER)
        self.fix_result_lbl.config(text="Applying fix...", fg=AMBER)
        t = threading.Thread(target=do_fix, daemon=True)
        t.start()

    def _fix_complete(self, result):
        ok = result.startswith("Fixed")
        self.fix_result_lbl.config(text=result, fg=GREEN if ok else RED)
        c = self.selected_check
        if c:
            self.tree.set(c.id, "Status", f"[{c.status}]")
            self.tree.set(c.id, "Details", c.details)
            alt = (c.id % 2 == 0)
            self.tree.item(c.id, tags=(c.status, "alt") if alt else (c.status,))
            self._show_detail(c)
            self.fix_btn.config(state=tk.DISABLED,
                                text="FIXED" if ok else "RETRY",
                                bg=GREEN if ok else RED)
            if ok and len(self.auditor.fix_history):
                self.undo_btn.config(state=tk.NORMAL)
            self._update_summary()

    def fix_all_auto_fixable(self):
        if not self.auditor.is_admin():
            messagebox.showwarning("Need Admin",
                "Run as Administrator to apply fixes.")
            return
        fixable = [c for c in self.auditor.checks
                   if c.status in ("FAIL", "WARNING") and c.auto_fixable]
        if not fixable:
            messagebox.showinfo("Nothing to Fix", "Everything looks good. No auto-fixable issues.")
            return

        names = "\n".join(f"  #{c.id:03d} {c.name}" for c in fixable)
        ok = messagebox.askyesno(
            "Fix all?",
            f"Fix {len(fixable)} things?\n\n{names}\n\n"
            "I'll create a restore point first. You can undo everything.")
        if not ok:
            return

        def do_fix_all():
            for c in fixable:
                r = self.auditor.fix_check(c, silent=True)
                done = len(self.auditor.fix_history)
                try:
                    self.root.after(0, lambda c=c, r=r: self._fix_all_progress(c, r, done, len(fixable)))
                except:
                    pass
            try:
                self.root.after(0, lambda: self._fix_all_complete())
            except:
                pass

        self.fix_all_btn.config(state=tk.DISABLED, text="FIXING...")
        t = threading.Thread(target=do_fix_all, daemon=True)
        t.start()

    def _fix_all_progress(self, check, result, done, total):
        self.tree.set(check.id, "Status", f"[{check.status}]")
        self.tree.set(check.id, "Details", check.details)
        alt = "alt" if (done % 2 == 0) else ""
        self.tree.item(check.id, tags=(check.status, alt) if alt else (check.status,))
        self.status_lbl.config(text=f"Fix [{done}/{total}]: #{check.id:03d} {check.name}")

    def undo_all_fixes(self):
        if not self.auditor.fix_history:
            messagebox.showinfo("Nothing to Undo", "You haven't fixed anything yet.")
            return
        names = "\n".join(f"  #{cid:03d} {desc}" for cid, desc in self.auditor.fix_history)
        ok = messagebox.askyesno(
            "Undo everything?",
            f"Revert {len(self.auditor.fix_history)} fix(es)?\n\n{names}\n\n"
            "I'll restore every registry key to its original value.")
        if not ok:
            return

        def do_undo():
            result = self.auditor.undo_all_fixes()
            try:
                self.root.after(0, lambda: self._undo_complete(result))
            except:
                pass

        self.undo_btn.config(state=tk.DISABLED, text="UNDOING...")
        t = threading.Thread(target=do_undo, daemon=True)
        t.start()

    def _undo_complete(self, result):
        self.undo_btn.config(state=tk.DISABLED, text="UNDO")
        self.fix_all_btn.config(state=tk.NORMAL, text="FIX ALL")
        self.status_lbl.config(text=result)
        for c in self.auditor.checks:
            self.tree.set(c.id, "Status", c.status)
            self.tree.set(c.id, "Details", c.details)
            alt = (c.id % 2 == 0)
            self.tree.item(c.id, tags=(c.status, "alt") if alt else (c.status,))
        self._update_summary()
        if self.selected_check:
            self._show_detail(self.selected_check)
        self.fix_btn.config(state=tk.DISABLED, text="FIX THIS", bg=RED)

    def _fix_all_complete(self):
        self.fix_all_btn.config(state=tk.NORMAL, text="FIX ALL")
        n = len(self.auditor.fix_history)
        self.undo_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text=f"Fixed {n} things. Click UNDO if you messed up.")
        self._update_summary()
        if self.selected_check:
            self._show_detail(self.selected_check)

    def _populate_initial(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, c in enumerate(self.auditor.checks):
            tags = (c.status, "alt") if i % 2 else (c.status,)
            self.tree.insert("", tk.END, iid=c.id, values=(
                f"#{c.id:03d}", c.category, c.name, c.status, c.description
            ), tags=tags)
        self.row_count_lbl.config(text=f"{len(self.auditor.checks)} items")

    def run_scan_thread(self):
        self.scan_complete = False
        self.run_btn.config(state=tk.DISABLED, text="SCANNING...", bg=GRAY)
        self.export_btn.config(state=tk.DISABLED)
        self.fix_all_btn.config(state=tk.DISABLED)
        self.progress_var.set(0)
        self.status_lbl.config(text="Initializing scan...")
        self.header_score.config(text="SCORE: --", fg=GRAY)

        for item in self.tree.get_children():
            self.tree.set(item, "Status", "...")
            self.tree.set(item, "Details", "")
            self.tree.item(item, tags=("PENDING",))

        t = threading.Thread(target=self._scan_process, daemon=True)
        t.start()

    def _scan_process(self):
        try:
            self.auditor.run_all_checks(progress_callback=self._update_progress)
        except Exception as e:
            self.root.after(0, lambda: self.status_lbl.config(
                text=f"Scan error: {str(e)}"))
        finally:
            self.root.after(0, self._scan_complete)

    def _update_progress(self, current, total, check):
        def ui_update():
            try:
                self.progress_var.set((current / max(total, 1)) * 100)
                self.status_lbl.config(text=f"[{current}/{total}] {check.name[:50]}")
                self.tree.set(check.id, "Status", f"[{check.status}]")
                self.tree.set(check.id, "Details", (check.details or "")[:120])
                tags = (check.status, "alt") if (current % 2 == 0) else (check.status,)
                self.tree.item(check.id, tags=tags)
                self.tree.see(check.id)
            except:
                pass
        self.root.after(0, ui_update)

    def _update_summary(self):
        passed = sum(1 for c in self.auditor.checks if c.status == "PASS")
        failed = sum(1 for c in self.auditor.checks if c.status == "FAIL")
        warned = sum(1 for c in self.auditor.checks if "WARN" in c.status)
        pending = sum(1 for c in self.auditor.checks if c.status == "PENDING")
        total = len(self.auditor.checks)
        score = round((passed / total) * 100, 1) if total else 0

        self._score_labels["pass"].config(text=f"PASS: {passed}")
        self._score_labels["fail"].config(text=f"FAIL: {failed}")
        self._score_labels["warn"].config(text=f"WARN: {warned}")
        self._score_labels["pending"].config(text=f"PENDING: {pending}")

        score_color = GREEN if score >= 70 else (AMBER if score >= 40 else RED)
        self.header_score.config(text=f"SCORE: {score}%", fg=score_color)

    def _update_trend(self):
        last = self.auditor.get_last_score()
        if last is None:
            self.header_trend.config(text="", fg=GRAY)
            return
        current = self.auditor._compute_score()
        diff = round(current - last, 1)
        if diff > 0:
            self.header_trend.config(text=f"Last: {last}%  ↑ +{diff}%", fg=GREEN)
        elif diff < 0:
            self.header_trend.config(text=f"Last: {last}%  ↓ {diff}%", fg=RED)
        else:
            self.header_trend.config(text=f"Last: {last}%  — same", fg=GRAY)

    def _scan_complete(self):
        self.scan_complete = True
        self.run_btn.config(state=tk.NORMAL, text="RUN SCAN", bg=ACCENT)
        self.export_btn.config(state=tk.NORMAL)
        self.fix_all_btn.config(state=tk.NORMAL)

        for i, c in enumerate(self.auditor.checks):
            self.tree.set(c.id, "Status", c.status)
            self.tree.set(c.id, "Details", c.details or "")
            alt = (c.id % 2 == 0)
            self.tree.item(c.id, tags=(c.status, "alt") if alt else (c.status,))

        self._update_summary()

        scan = self.auditor.save_scan()
        self._load_history_panel()
        self._update_trend()

        fixable = sum(1 for c in self.auditor.checks
                      if c.status in ("FAIL", "WARNING") and c.auto_fixable)
        if fixable:
            self.status_lbl.config(text=f"Done. {fixable} things can be auto-fixed.")
        else:
            self.status_lbl.config(text="Done. Nothing to auto-fix. Your system looks good.")

    def export_report(self):
        if not self.scan_complete:
            messagebox.showwarning("Nothing to Export", "Run a scan first.")
            return

        fmt = self.export_format.get()
        fmt_info = FORMATS[fmt]
        filepath = filedialog.asksaveasfilename(
            defaultextension=fmt_info["ext"],
            filetypes=[(fmt_info["desc"], f"*{fmt_info['ext']}")],
            initialfile=f"CISO_Audit_Report{fmt_info['ext']}",
            title="Save Report"
        )
        if not filepath:
            return

        def do_export():
            try:
                result = save_report(self.auditor.checks, fmt=fmt, filepath=filepath)
                self.root.after(0, lambda: messagebox.showinfo(
                    "Done", f"Saved to:\n{result}"))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    "Export Failed", str(e)))

        t = threading.Thread(target=do_export, daemon=True)
        t.start()
        self.status_lbl.config(text=f"Exporting {fmt.upper()}...")

if __name__ == "__main__":
    root = tk.Tk()
    app = CISOAuditorApp(root)
    root.mainloop()
