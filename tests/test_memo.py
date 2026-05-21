"""Smoke tests for the Finding Memo + triage logic."""

from __future__ import annotations

from evidencememo.investigator import _is_private_ip, _triage_processes
from evidencememo.memo import Evidence, Finding, FindingMemo, Severity
from evidencememo.volatility import VolatilityResult


def test_memo_renders_with_findings() -> None:
    memo = FindingMemo(
        case_name="case-001.mem",
        hypothesis="Possible Cobalt Strike beacon",
        os_profile="windows",
        investigation_steps=8,
        self_corrections=1,
        findings=[
            Finding(
                severity=Severity.CRITICAL,
                title="Suspicious svchost (PID 4321)",
                claim="Orphaned svchost — known malware pattern.",
                evidence=[Evidence(plugin="windows.pslist", offset="0x82345f60", extract="svchost.exe PID 4321 PPID 1")],
            )
        ],
    )
    md = memo.to_markdown()
    assert "CRITICAL" in md
    assert "0x82345f60" in md
    assert "windows.pslist" in md
    assert "Self-corrections during run:** 1" in md


def test_private_ip_detection() -> None:
    assert _is_private_ip("10.0.0.1")
    assert _is_private_ip("192.168.1.1")
    assert _is_private_ip("172.16.0.5")
    assert _is_private_ip("127.0.0.1")
    assert not _is_private_ip("198.51.100.42")
    assert not _is_private_ip("8.8.8.8")


def test_triage_finds_typosquat() -> None:
    pslist = VolatilityResult(
        plugin="windows.pslist",
        profile="windows",
        raw_stdout="",
        looks_valid=True,
        rows=[
            {"PID": "100", "PPID": "612", "ImageFileName": "svchost.exe", "Offset(V)": "0x1"},
            {"PID": "4321", "PPID": "1", "ImageFileName": "scvhost", "Offset(V)": "0xdeadbeef"},
        ],
    )
    findings = _triage_processes(pslist)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_triage_finds_orphaned_svchost() -> None:
    pslist = VolatilityResult(
        plugin="windows.pslist",
        profile="windows",
        raw_stdout="",
        looks_valid=True,
        rows=[
            {"PID": "1500", "PPID": "999", "ImageFileName": "svchost.exe", "Offset(V)": "0x82345f60"},
        ],
    )
    findings = _triage_processes(pslist)
    # 999 is not in the legit services PPID set {612, 624, 744}
    assert any("orphan" in (f.title.lower() + f.claim.lower()) or "non-services" in (f.title.lower() + f.claim.lower()) for f in findings)
