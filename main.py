#!/usr/bin/env python3
from __future__ import annotations

def main():
    try:
        import tkinter as tk
    except Exception as e:
        raise SystemExit(
            "Tkinter is not available. On Debian/Kali install it with:\n"
            "  sudo apt update && sudo apt install -y python3-tk\n"
            f"Error: {e}"
        )

    from src.gui.app import App
    root = tk.Tk()
    root.title("Sophos Firewall Backup CIS-style Audit Tool")
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
