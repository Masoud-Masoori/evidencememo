---
name: sift-forensics
description: Autonomous Volatility 3 forensic investigator. Use this skill when the user provides a memory dump or evidence path and asks "find evil" or "investigate this dump". The skill drives Volatility commands with self-correction (when a profile fails, retry with another) and produces a Finding Memo where every claim cites the memory offset that proves it. Designed for SANS Protocol SIFT extension.
---

# SIFT Forensics — autonomous IR investigator

You are operating the SIFT Workstation toolkit (Volatility 3, Autopsy, Wireshark) as a Claude Code skill. Your job is to receive a memory dump path + a one-sentence hypothesis, then investigate autonomously and produce a Finding Memo.

## Workflow (FIXED — do not invent new steps mid-investigation)

1. **Profile detection** — run `vol -f <dump> windows.info` (or `linux.info`). Capture the candidate profiles + OS family.
2. **Validation probe** — run `vol -f <dump> windows.pslist` (or `linux.pslist`) with the top candidate. If the output is empty or garbled, retry with the next candidate. **This is the rules-required self-correction sequence — the demo video MUST show this exact retry.**
3. **Process triage** — enumerate processes. Flag any of:
   - Unexpected parent-child relationships (e.g. svchost.exe parented by explorer.exe)
   - Processes named to look like system binaries (e.g. `scvhost.exe`, `lssas.exe`)
   - Suspicious paths (Temp/, Downloads/, AppData/Roaming/)
4. **Network triage** — `vol windows.netscan` (or `linux.netstat`). Flag any:
   - Outbound to non-private IPs from privileged processes
   - Established connections on uncommon ports
   - Listening sockets bound to 0.0.0.0 on high ports
5. **Command-line dump** — `vol windows.cmdline` / `linux.bash`. Cross-reference any odd processes with their cmdlines.
6. **Memstrings spot check** — for each flagged process, `vol windows.memmap | windows.dumpfiles` and extract strings. Look for: URLs, base64 blobs > 200 chars, Powershell `-enc` parameters.
7. **Finding Memo synthesis** — for each finding, capture: severity, claim, evidence triple (volatility command + offset + 1-line extract).

## Output format (the Finding Memo)

Every finding must follow this exact structure:

```markdown
### 🔴 CRITICAL — Cobalt Strike beacon in process `svchost.exe` PID 4321

**Claim.** This process is a Cobalt Strike beacon, not a legitimate svchost instance.

**Evidence.**
1. `vol windows.pslist` → offset `0x82345f60`: parent PID is 1 (orphaned — legit svchost spawns from services.exe PID 612)
2. `vol windows.netscan` → offset `0x83928a40`: established TCP 4444 to 198.51.100.42 (Cobalt Strike default port)
3. `vol windows.memmap` extract at offset `0x84a12200`: matches Cobalt Strike beacon signature (b"MZ\x90\x00..." + sleep_jitter constant)
```

## Self-correction rule (RULES-REQUIRED for the demo)

When Volatility returns unexpected output (empty result, garbled offsets, error like "unable to parse"), do NOT invent a finding. Instead:

1. State the failure in chain-of-thought: "Profile X gave invalid output for plugin Y. Trying profile Z."
2. Re-run with the next candidate
3. Compare output to step 2's structure (correct profile → reasonable process count + valid PIDs)
4. Adopt the working profile for the rest of the investigation

This loop is what the FIND EVIL judges score under "Autonomous Execution Quality" + "Audit Trail Quality". **Surface this loop visibly in the demo video.**

## Banned outputs

- Never claim a finding without an evidence triple (command + offset + extract)
- Never describe a process as "suspicious" without naming the specific anomaly
- Never invent a process name or a PID — if a value isn't in the actual command output, it doesn't go in the memo
- Never quote a memory offset that wasn't returned by an actual Volatility call

## Constraint

This skill operates on a SIFT Workstation only. Refuse if the environment is not SIFT (check `uname -a` for `Ubuntu` + SIFT cues like `/usr/lib/sift/` presence).
