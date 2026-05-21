"""Volatility 3 subprocess wrapper.

Volatility plugin calls return mixed-format text. This module:
1. Shells out to `vol -f <dump> <plugin>`
2. Parses common-shape output into structured Python (dicts)
3. Reports "garbage output" honestly so the self-correction loop can retry

Volatility is the heart of SIFT forensics. Pinning to volatility3==2.7.0
in pyproject.toml per the operator's policy.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass
from typing import Any


@dataclass
class VolatilityResult:
    plugin: str
    profile: str | None
    raw_stdout: str
    rows: list[dict[str, str]]
    looks_valid: bool
    failure_reason: str = ""


class VolatilityNotInstalled(RuntimeError):
    pass


def assert_volatility_available() -> None:
    if not shutil.which("vol") and not shutil.which("vol.py") and not shutil.which("volatility3"):
        raise VolatilityNotInstalled(
            "Volatility 3 binary not found on PATH. "
            "On SIFT Workstation: `sudo apt install volatility3` or `pip install volatility3`."
        )


async def run_plugin(
    dump_path: str,
    plugin: str,
    *,
    profile: str | None = None,
    timeout_seconds: int = 120,
) -> VolatilityResult:
    """Invoke a single volatility plugin and return parsed rows."""
    assert_volatility_available()

    argv = ["vol", "-f", dump_path, plugin]
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
    except TimeoutError:
        proc.kill()
        return VolatilityResult(
            plugin=plugin, profile=profile, raw_stdout="", rows=[],
            looks_valid=False, failure_reason=f"plugin {plugin} timed out after {timeout_seconds}s",
        )

    stdout = stdout_b.decode("utf-8", errors="ignore")
    stderr = stderr_b.decode("utf-8", errors="ignore")

    if proc.returncode != 0:
        return VolatilityResult(
            plugin=plugin, profile=profile, raw_stdout=stdout, rows=[],
            looks_valid=False, failure_reason=stderr[:400],
        )

    rows = _parse_table(stdout)
    looks_valid, reason = _heuristic_valid(plugin, rows, stdout)
    return VolatilityResult(plugin=plugin, profile=profile, raw_stdout=stdout, rows=rows, looks_valid=looks_valid, failure_reason=reason)


def _parse_table(stdout: str) -> list[dict[str, str]]:
    """Parse Volatility's tab-delimited output → list[dict]."""
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return []
    # First non-empty line after banner is usually the header
    header_idx = _find_header(lines)
    if header_idx < 0:
        return []
    header = re.split(r"\s{2,}|\t", lines[header_idx].strip())
    rows: list[dict[str, str]] = []
    for line in lines[header_idx + 1 :]:
        cols = re.split(r"\s{2,}|\t", line.strip())
        if len(cols) < 2:
            continue
        row = {h: (cols[i] if i < len(cols) else "") for i, h in enumerate(header)}
        rows.append(row)
    return rows


def _find_header(lines: list[str]) -> int:
    """Most Volatility plugins emit a header containing 'PID' or 'Offset'."""
    for i, line in enumerate(lines):
        if any(k in line for k in ("PID", "Offset", "Name", "Owner", "Path")):
            return i
    return -1


def _heuristic_valid(plugin: str, rows: list[dict[str, str]], stdout: str) -> tuple[bool, str]:
    """Heuristic check: does the output look like a sane plugin response?"""
    if plugin.endswith("pslist") or plugin.endswith("ps"):
        if len(rows) < 3:
            return False, f"{plugin} returned only {len(rows)} rows — wrong profile or corrupt dump?"
        # PIDs should look numeric
        numeric_pids = sum(1 for r in rows if (r.get("PID", "") or "").strip().isdigit())
        if numeric_pids < len(rows) * 0.7:
            return False, f"{plugin}: only {numeric_pids}/{len(rows)} rows have numeric PIDs"
        return True, ""
    if plugin.endswith("info"):
        if "Symbols" not in stdout and "Volatility" not in stdout:
            return False, "info plugin output missing expected banner"
        return True, ""
    return len(rows) > 0, "" if rows else f"{plugin} returned no rows"
