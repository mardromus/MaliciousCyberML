"""Automated response engine.

Consumes PowerShell script-block events (the fields of Windows Event ID 4104,
produced when Script Block Logging is enabled), scores them with a trained
model, maps behavioural indicators to MITRE ATT&CK techniques and selects a
proportionate response. Actions run in dry-run mode by default: each one is
written to an append-only audit log instead of touching the host, which is how
a SOAR playbook is normally validated before it is allowed to act.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum

from .features import indicator_hits, normalise

# Indicator group -> (ATT&CK technique id, name)
ATTACK_MAP = {
    "exec_dynamic": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "download": ("T1105", "Ingress Tool Transfer"),
    "encoding": ("T1027", "Obfuscated Files or Information"),
    "win32_api": ("T1055", "Process Injection"),
    "defense_evasion": ("T1562.001", "Impair Defenses: Disable or Modify Tools"),
    "persistence": ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    "credential": ("T1003.001", "OS Credential Dumping: LSASS Memory"),
    "network_socket": ("T1095", "Non-Application Layer Protocol"),
    "reflection": ("T1620", "Reflective Code Loading"),
}
HIGH_IMPACT = {"win32_api", "credential", "reflection"}


class Tier(IntEnum):
    ALLOW = 0
    ALERT = 1
    CONTAIN = 2
    ISOLATE = 3


@dataclass
class Policy:
    alert_threshold: float = 0.30
    contain_threshold: float = 0.70
    isolate_threshold: float = 0.95
    require_analyst_for_isolation: bool = True


@dataclass
class Decision:
    event_id: str
    host: str
    score: float
    tier: str
    techniques: list
    actions: list
    iocs: dict
    latency_ms: float
    analyst_approval_required: bool = False
    extra: dict = field(default_factory=dict)


_URL = re.compile(r"https?://[^\s'\"\)]+", re.I)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang(ioc: str) -> str:
    return ioc.replace("http", "hxxp").replace(".", "[.]")


def extract_iocs(text: str) -> dict:
    urls = sorted(set(_URL.findall(text)))
    ips = sorted(set(_IP.findall(text)))
    return {"urls": [defang(u) for u in urls][:20], "ips": [defang(i) for i in ips][:20]}


class ResponseEngine:
    def __init__(self, model, policy: Policy | None = None, audit_path: str | None = None,
                 dry_run: bool = True):
        self.model = model
        self.policy = policy or Policy()
        self.audit_path = audit_path
        self.dry_run = dry_run

    def _tier(self, score: float, groups: set) -> Tier:
        p = self.policy
        if score >= p.isolate_threshold and groups & HIGH_IMPACT:
            return Tier.ISOLATE
        if score >= p.contain_threshold:
            return Tier.CONTAIN
        if score >= p.alert_threshold:
            return Tier.ALERT
        return Tier.ALLOW

    def _plan(self, tier: Tier, event: dict, iocs: dict) -> list:
        sha = hashlib.sha256(event["ScriptBlockText"].encode()).hexdigest()
        actions = [{"type": "log", "detail": "record verdict in SIEM"}]
        if tier >= Tier.ALERT:
            actions.append({"type": "raise_alert", "detail": "open SOC ticket with ATT&CK context"})
        if tier >= Tier.CONTAIN:
            actions.append({"type": "terminate_process", "pid": event.get("ProcessId")})
            if event.get("Path"):
                actions.append({"type": "quarantine_file", "path": event["Path"], "sha256": sha})
            actions.append({"type": "block_hash", "sha256": sha})
            if iocs["urls"] or iocs["ips"]:
                actions.append({"type": "block_network_iocs",
                                "count": len(iocs["urls"]) + len(iocs["ips"])})
        if tier >= Tier.ISOLATE:
            actions.append({"type": "isolate_host", "host": event.get("Computer")})
        for a in actions:
            a["status"] = "simulated" if self.dry_run else "executed"
        return actions

    def handle(self, event: dict) -> Decision:
        t0 = time.perf_counter()
        text = event["ScriptBlockText"]
        score = float(self.model.predict_proba([text])[:, 1][0])
        hits = indicator_hits(normalise(text))
        groups = {g for g, c in hits.items() if c > 0}
        tier = self._tier(score, groups)
        techniques = [{"id": ATTACK_MAP[g][0], "name": ATTACK_MAP[g][1], "evidence_count": hits[g]}
                      for g in sorted(groups)]
        iocs = extract_iocs(text) if tier >= Tier.ALERT else {"urls": [], "ips": []}
        actions = self._plan(tier, event, iocs)
        latency = (time.perf_counter() - t0) * 1000
        decision = Decision(
            event_id=str(event.get("ScriptBlockId")), host=str(event.get("Computer")),
            score=round(score, 4), tier=tier.name, techniques=techniques, actions=actions,
            iocs=iocs, latency_ms=round(latency, 2),
            analyst_approval_required=(tier == Tier.ISOLATE
                                       and self.policy.require_analyst_for_isolation),
        )
        if self.audit_path:
            with open(self.audit_path, "a") as fh:
                fh.write(json.dumps(asdict(decision)) + "\n")
        return decision
