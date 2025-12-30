from __future__ import annotations

import argparse
import os
import sys

from .core.backup import extract_sophos_backup, SophosBackupError
from .core.corpus import ConfigCorpus
from .core.engine import run_rules
from .rules.sophos_rules import default_rules
from .report.pdf_report import build_pdf

def main():
    ap = argparse.ArgumentParser(description="Sophos Firewall backup configuration audit (CIS-style).")
    ap.add_argument("--backup", required=True, help="Path to Sophos admin backup file")
    ap.add_argument("--password", default=None, help="Backup encryption password (if encrypted)")
    ap.add_argument("--out", required=True, help="Output PDF path")
    args = ap.parse_args()

    try:
        res = extract_sophos_backup(args.backup, args.password)
        corpus = ConfigCorpus(res.work_dir)
        findings = run_rules(corpus, default_rules())
        build_pdf(args.out, findings, backup_name=os.path.basename(args.backup), notes=res.notes)
        print(f"Wrote: {args.out}")
        return 0
    except SophosBackupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"UNEXPECTED ERROR: {e}", file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
