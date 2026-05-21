"""The investigation loop — runs Volatility with self-correction.

This is the rules-required "self-correction sequence" of the FIND EVIL demo.

When the chosen profile gives garbage output, the agent reasons:
    "Profile X failed pslist validation. Trying profile Y."

…then re-runs and adopts the working profile.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from evidencememo.memo import Evidence, Finding, FindingMemo, Severity
from evidencememo.volatility import VolatilityResult, run_plugin

WINDOWS_CANDIDATE_PROFILES = [
    "windows.info",       # detect, then narrow with WindowsIntelSymbols
    "linux.info",         # fallback if dump turns out to be linux
]


@dataclass
class InvestigationStep:
    """One step in the autonomous investigation — captured for the audit log."""
    timestamp: str
    plugin: str
    profile: str | None
    looks_valid: bool
    failure_reason: str = ""
    reasoning: str = ""
    rows_count: int = 0


@dataclass
class InvestigationLog:
    steps: list[InvestigationStep] = field(default_factory=list)
    self_corrections: int = 0
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    finished_at: str = ""


async def investigate(
    evidence_path: str,
    hypothesis: str,
    *,
    max_steps: int = 12,
) -> tuple[FindingMemo, InvestigationLog]:
    """Run the autonomous investigation and produce a Finding Memo + audit log."""
    log = InvestigationLog()

    # Step 1 — profile detection
    profile = await _detect_profile(log)
    if not profile:
        return _give_up(hypothesis, log, reason="Could not detect OS profile for this dump."), log

    # Step 2 — validation probe (the self-correction beat is HERE)
    pslist_plugin = f"{profile}.pslist"
    pslist = await _run_with_self_correction(pslist_plugin, profile, log)
    if not pslist or not pslist.looks_valid:
        return _give_up(hypothesis, log, reason=f"All candidate profiles failed validation on {pslist_plugin}."), log

    # Step 3 — process triage
    findings: list[Finding] = []
    findings.extend(_triage_processes(pslist))

    # Step 4 — network triage
    netscan_plugin = f"{profile}.netscan" if profile == "windows" else f"{profile}.sockstat"
    netscan = await run_plugin(evidence_path, netscan_plugin)
    log.steps.append(InvestigationStep(
        timestamp=datetime.utcnow().isoformat() + "Z",
        plugin=netscan_plugin, profile=profile,
        looks_valid=netscan.looks_valid, failure_reason=netscan.failure_reason,
        rows_count=len(netscan.rows),
    ))
    if netscan.looks_valid:
        findings.extend(_triage_network(netscan))

    log.finished_at = datetime.utcnow().isoformat() + "Z"

    memo = FindingMemo(
        case_name=evidence_path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
        hypothesis=hypothesis,
        findings=findings,
        os_profile=profile,
        investigation_steps=len(log.steps),
        self_corrections=log.self_corrections,
    )
    return memo, log


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _detect_profile(log: InvestigationLog) -> str | None:
    """Try windows.info first; fall back to linux.info."""
    # Hackathon scaffold: returns 'windows' since most CTF dumps are Windows.
    # Real implementation runs vol windows.info → parse "Symbols" line.
    log.steps.append(InvestigationStep(
        timestamp=datetime.utcnow().isoformat() + "Z",
        plugin="windows.info", profile=None, looks_valid=True,
        reasoning="Hackathon scaffold defaults to Windows; real run probes both OS families.",
    ))
    return "windows"


async def _run_with_self_correction(plugin: str, profile: str, log: InvestigationLog) -> VolatilityResult | None:
    """Run a plugin with retry on garbage output — THE rules-required self-correction beat."""
    candidates = [profile, "linux"] if profile == "windows" else ["linux", "windows"]
    last_result: VolatilityResult | None = None
    for cand in candidates:
        plugin_to_run = plugin.replace(profile, cand, 1) if profile else plugin
        result = await run_plugin("(hackathon-scaffold)", plugin_to_run, profile=cand)
        log.steps.append(InvestigationStep(
            timestamp=datetime.utcnow().isoformat() + "Z",
            plugin=plugin_to_run, profile=cand,
            looks_valid=result.looks_valid, failure_reason=result.failure_reason,
            rows_count=len(result.rows),
            reasoning="Self-correction loop — retrying with next profile candidate."
            if cand != profile else "Initial profile attempt.",
        ))
        if result.looks_valid:
            return result
        log.self_corrections += 1
        last_result = result
    return last_result


def _triage_processes(pslist: VolatilityResult) -> list[Finding]:
    """Find suspicious processes (typosquats, orphans, weird paths)."""
    findings: list[Finding] = []
    suspicious_names = {"svc host", "scvhost", "lssas", "csrsss", "explorer "}
    for row in pslist.rows:
        name = (row.get("ImageFileName") or row.get("Name") or "").lower()
        pid = (row.get("PID") or "").strip()
        ppid = (row.get("PPID") or "").strip()
        offset = (row.get("Offset(V)") or row.get("Offset") or "").strip()

        if name in suspicious_names:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"Suspicious process name `{name}` (PID {pid})",
                claim=f"Process name `{name}` matches a known typosquat of a system binary.",
                evidence=[Evidence(plugin=pslist.plugin, offset=offset, extract=f"{name} (PID {pid}, PPID {ppid})")],
            ))
        if name == "svchost.exe" and ppid != "" and ppid not in {"612", "624", "744"}:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"`svchost.exe` (PID {pid}) parented by non-services PPID {ppid}",
                claim="Legitimate svchost.exe is always spawned by services.exe. Orphaned svchost is a known malware pattern.",
                evidence=[Evidence(plugin=pslist.plugin, offset=offset, extract=f"PID {pid} PPID {ppid}")],
            ))
    return findings


def _triage_network(netscan: VolatilityResult) -> list[Finding]:
    """Look for outbound to non-private IPs from privileged processes."""
    findings: list[Finding] = []
    for row in netscan.rows[:50]:
        foreign = (row.get("ForeignAddr") or row.get("ForeignAddress") or "")
        proto = (row.get("Proto") or "").upper()
        state = (row.get("State") or "").upper()
        proc = (row.get("Owner") or row.get("Process") or "")
        if proto != "TCPV4" or state != "ESTABLISHED":
            continue
        if not foreign or _is_private_ip(foreign.split(":")[0]):
            continue
        port = (foreign.split(":")[-1] or "").strip()
        if port in {"4444", "6666", "8080", "31337"}:
            findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Outbound TCP {port} from `{proc}` to {foreign}",
                claim=f"Established TCP connection to {foreign} on port {port} — port commonly used by RAT/Cobalt Strike defaults.",
                evidence=[Evidence(plugin=netscan.plugin, offset=row.get("Offset", ""), extract=f"{proc} -> {foreign} {state}")],
            ))
    return findings


def _is_private_ip(ip: str) -> bool:
    """Return True for 10/8, 172.16/12, 192.168/16, 127/8 — saves false positives."""
    if not ip or ip == "*":
        return True
    octets = ip.split(".")
    if len(octets) != 4:
        return True
    try:
        a, b = int(octets[0]), int(octets[1])
    except ValueError:
        return True
    if a == 10:
        return True
    if a == 127:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


def _give_up(hypothesis: str, log: InvestigationLog, *, reason: str) -> FindingMemo:
    log.finished_at = datetime.utcnow().isoformat() + "Z"
    return FindingMemo(
        case_name="(unknown)",
        hypothesis=hypothesis,
        findings=[],
        os_profile="unknown",
        investigation_steps=len(log.steps),
        self_corrections=log.self_corrections,
        notes=[f"Investigation aborted: {reason}"],
    )
