from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from .corpus import ConfigCorpus, Evidence

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_MANUAL = "MANUAL"

@dataclass
class Finding:
    issue_id: str
    issue_name: str
    status: str
    fix_type: str  # Quick/Involved/Planned
    remediation: str
    evidence: str

RuleFn = Callable[[ConfigCorpus], Finding]

def _mk(issue_id: str, name: str, status: str, fix_type: str, remediation: str, ev: Optional[Sequence[Evidence]] = None) -> Finding:
    evidence = ""
    if ev:
        lines = [f"{e.file}: {e.snippet}" for e in ev[:3]]
        evidence = "\n".join(lines)
    return Finding(issue_id=issue_id, issue_name=name, status=status, fix_type=fix_type, remediation=remediation, evidence=evidence)

def run_rules(corpus: ConfigCorpus, rules: Sequence[RuleFn]) -> List[Finding]:
    findings: List[Finding] = []
    for fn in rules:
        try:
            findings.append(fn(corpus))
        except Exception as e:
            findings.append(_mk("FW-ERR", f"Rule execution error: {getattr(fn,'__name__','rule')}", STATUS_UNKNOWN, "Planned", "Fix rule implementation.", [Evidence(file="(tool)", snippet=str(e))]))
    return findings
