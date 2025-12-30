# Sophos Firewall Backup CIS-style Audit Tool (SFOS)

This tool reviews **Sophos Firewall (SFOS)** configuration from an **Admin Backup** file and generates a **PDF report** with CIS-style findings:
- Issue ID
- Issue name
- Status (PASS/FAIL/UNKNOWN)
- Evidence (file + snippet)
- Remediation guidance
- Fix type (Quick/Involved/Planned)

## Why a password is required
SFOS Admin Backups are typically encrypted using OpenSSL-compatible salted encryption (`Salted__` header). You need the backup encryption password configured on the firewall at export time.

## Quick start (Linux/Kali)
```bash
cd sophos_backup_cis_audit
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python main.py
```

## CLI usage (headless)
```bash
source .venv/bin/activate
python -m src.cli --backup "/path/to/admin_Backup_..." --password "YOUR_PASSWORD" --out report.pdf
```

## Notes
- The parser is **heuristic** and resilient: it extracts the backup archive, searches for XML/text configuration artifacts, and applies rule patterns.
- Some checks may show **UNKNOWN** when the relevant configuration key cannot be found in the backup artifacts.


## Tkinter dependency (GUI)
On some Kali/Debian builds, Tkinter is not installed by default.

```bash
sudo apt update && sudo apt install -y python3-tk
```
