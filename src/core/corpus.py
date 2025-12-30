from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

TEXT_EXT = {".xml", ".conf", ".cfg", ".txt", ".dump", ".ini", ".json", ".log"}

@dataclass
class Evidence:
    file: str
    snippet: str

class ConfigCorpus:
    def __init__(self, root_dir: str, max_bytes_per_file: int = 2_000_000):
        self.root_dir = os.path.abspath(root_dir)
        self.max_bytes_per_file = max_bytes_per_file
        self._texts: List[Tuple[str, str]] = []  # (relpath, content)
        self._load()

    def _load(self):
        for r, _, files in os.walk(self.root_dir):
            for fn in files:
                full = os.path.join(r, fn)
                rel = os.path.relpath(full, self.root_dir)
                ext = os.path.splitext(fn)[1].lower()
                # also attempt small files even if extension unknown
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    continue
                if sz == 0:
                    continue
                if sz > self.max_bytes_per_file:
                    continue
                if ext in TEXT_EXT or sz < 200_000:
                    try:
                        with open(full, "rb") as f:
                            data = f.read()
                        # decode best-effort
                        txt = data.decode("utf-8", errors="ignore")
                        if txt.strip():
                            self._texts.append((rel, txt))
                    except Exception:
                        continue

    def grep(self, pattern: str, flags: int = re.IGNORECASE, max_matches: int = 5) -> List[Evidence]:
        rx = re.compile(pattern, flags)
        out: List[Evidence] = []
        for rel, txt in self._texts:
            for m in rx.finditer(txt):
                start = max(m.start() - 120, 0)
                end = min(m.end() + 120, len(txt))
                snippet = txt[start:end].replace("\n", " ").replace("\r", " ")
                out.append(Evidence(file=rel, snippet=snippet))
                if len(out) >= max_matches:
                    return out
        return out

    def has(self, pattern: str, flags: int = re.IGNORECASE) -> bool:
        return len(self.grep(pattern, flags=flags, max_matches=1)) > 0
