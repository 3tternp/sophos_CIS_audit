from __future__ import annotations

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from ..core.backup import extract_sophos_backup, SophosBackupError
from ..core.corpus import ConfigCorpus
from ..core.engine import run_rules
from ..rules.sophos_rules import default_rules
from ..report.pdf_report import build_pdf

class App:
    def __init__(self, master: tk.Tk):
        self.master = master
        self.backup_path = tk.StringVar()
        self.password = tk.StringVar()
        self.out_pdf = tk.StringVar(value=os.path.join(os.getcwd(), "sophos_firewall_audit_report.pdf"))
        self.status = tk.StringVar(value="Ready.")
        self.findings = []

        self._build()

    def _build(self):
        frm = ttk.Frame(self.master, padding=12)
        frm.pack(fill="both", expand=True)

        # Backup file
        row = 0
        ttk.Label(frm, text="Sophos Backup File:").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.backup_path, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Browse", command=self.browse_backup).grid(row=row, column=2, sticky="e")
        row += 1

        # Password
        ttk.Label(frm, text="Backup Password (if encrypted):").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.password, width=40, show="*").grid(row=row, column=1, sticky="w", padx=6)
        row += 1

        # Output
        ttk.Label(frm, text="Output PDF:").grid(row=row, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.out_pdf, width=80).grid(row=row, column=1, sticky="we", padx=6)
        ttk.Button(frm, text="Choose", command=self.choose_out).grid(row=row, column=2, sticky="e")
        row += 1

        # Buttons
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=8)
        ttk.Button(btns, text="Run Audit", command=self.run_clicked).pack(side="left")
        ttk.Button(btns, text="Open PDF Location", command=self.open_pdf_location).pack(side="left", padx=8)
        row += 1

        # Progress and status
        self.progress = ttk.Progressbar(frm, mode="indeterminate")
        self.progress.grid(row=row, column=0, columnspan=3, sticky="we", pady=6)
        row += 1
        ttk.Label(frm, textvariable=self.status).grid(row=row, column=0, columnspan=3, sticky="w")
        row += 1

        # Results table
        cols = ("issue_id", "issue_name", "status", "fix_type")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c.replace("_"," ").title())
        self.tree.column("issue_id", width=110, anchor="w")
        self.tree.column("issue_name", width=520, anchor="w")
        self.tree.column("status", width=90, anchor="center")
        self.tree.column("fix_type", width=110, anchor="center")
        self.tree.grid(row=row, column=0, columnspan=3, sticky="nsew", pady=8)

        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(row, weight=1)

    def browse_backup(self):
        p = filedialog.askopenfilename(title="Select Sophos Firewall Backup")
        if p:
            self.backup_path.set(p)

    def choose_out(self):
        p = filedialog.asksaveasfilename(title="Save PDF Report", defaultextension=".pdf",
                                         filetypes=[("PDF files", "*.pdf")])
        if p:
            self.out_pdf.set(p)

    def open_pdf_location(self):
        path = self.out_pdf.get().strip()
        if not path:
            messagebox.showwarning("No output path", "Set an output PDF path first.")
            return
        folder = os.path.dirname(os.path.abspath(path)) or os.getcwd()
        try:
            if os.name == "nt":
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                import subprocess
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Open folder failed", str(e))

    def run_clicked(self):
        backup = self.backup_path.get().strip()
        if not backup or not os.path.exists(backup):
            messagebox.showerror("Missing backup", "Select a valid Sophos backup file.")
            return

        out = self.out_pdf.get().strip()
        if not out.lower().endswith(".pdf"):
            out += ".pdf"
            self.out_pdf.set(out)

        pwd = self.password.get()
        pwd = pwd if pwd.strip() else None

        self.status.set("Running audit...")
        self.progress.start(10)

        def worker():
            try:
                res = extract_sophos_backup(backup, pwd)
                corpus = ConfigCorpus(res.work_dir)
                findings = run_rules(corpus, default_rules())
                build_pdf(out, findings, backup_name=os.path.basename(backup), notes=res.notes)

                def ui():
                    self.tree.delete(*self.tree.get_children())
                    for f in findings:
                        self.tree.insert("", tk.END, values=(f.issue_id, f.issue_name, f.status, f.fix_type))
                    self.status.set(f"Done. Findings: {len(findings)}. PDF: {out}")
                    messagebox.showinfo("Audit complete", f"Report generated:\n{out}")
                self.master.after(0, ui)

            except SophosBackupError as e:
                self.master.after(0, lambda: messagebox.showerror("Backup processing error", str(e)))
                self.master.after(0, lambda: self.status.set("Failed."))
            except Exception as e:
                self.master.after(0, lambda: messagebox.showerror("Unexpected error", str(e)))
                self.master.after(0, lambda: self.status.set("Failed."))
            finally:
                self.master.after(0, lambda: self.progress.stop())

        threading.Thread(target=worker, daemon=True).start()
