# EvidenceMemo

> Autonomous Claude Code forensic investigator on SIFT. Every finding cites the exact memory offset that proves it.

Built for the [FIND EVIL!](https://findevil.devpost.com/) hackathon — track: SLAYED EVIL ($10K + SANS Summit pass).

## What it does

Give it a memory dump + a one-sentence hypothesis. It runs Volatility 3 autonomously, **self-corrects** when a profile fails, and writes a Finding Memo + execution log.

```bash
evidencememo investigate /cases/case-001/memory.dmp \
    --hypothesis "Possible Cobalt Strike beacon" \
    --out-memo finding-memo.md \
    --out-log investigation-log.jsonl
```

Output: every finding in `finding-memo.md` has an Evidence triple:

```markdown
### 🔴 CRITICAL — Suspicious svchost (PID 4321)
Claim. Orphaned svchost — known malware pattern.

Evidence.
1. windows.pslist @ offset 0x82345f60: svchost.exe PID 4321 PPID 1
```

The Claude Code skill at `skills/sift-forensics/SKILL.md` documents the FIXED workflow + the rules-required self-correction beat.

## The rules-required self-correction sequence

FIND EVIL judges score "Autonomous Execution Quality" + "Audit Trail Quality". The demo video **must show one self-correction sequence on camera.** EvidenceMemo's self-correction loop runs when:

1. `vol windows.info` returns multiple candidate profiles
2. We pick profile A → `vol windows.pslist` → output has 0 rows or non-numeric PIDs
3. Agent reasons: "Profile A failed pslist validation, trying profile B"
4. Re-runs with profile B → output is sensible (200+ processes, valid PIDs)
5. Adopts profile B for the rest of the investigation

The investigation log (JSONL) captures every step + reasoning + retry — that's the audit trail.

## Architecture

```
[Operator]
   │
   │  evidencememo investigate <dump> --hypothesis "..."
   v
[CLI (typer)]
   │
   v
[investigator.investigate()]
   │
   ├─ _detect_profile()   ───►  vol -f <dump> windows.info  /  linux.info
   │
   ├─ _run_with_self_correction()  ───►  vol -f <dump> <plugin>  (retry on garbage)
   │
   ├─ _triage_processes()  ───►  finds typosquats + orphaned svchost
   │
   ├─ _triage_network()   ───►  outbound to non-private IPs on RAT ports
   │
   v
[FindingMemo.to_markdown()]
   │
   v
[finding-memo.md  +  investigation-log.jsonl]
```

## Pre-reqs

- SIFT Workstation 22.04+ (`https://digital-forensics.sans.org/community/downloads`)
- Volatility 3 (`sudo apt install volatility3` OR `pip install volatility3==2.7.0`)
- Sample memory dump for the demo:
  - SANS public CTF challenges (Holiday Hack, Force Awakens DFIR)
  - Volatility official sample at `https://github.com/volatilityfoundation/volatility3/wiki/Memory-Samples`

## Quickstart

```bash
cd code/evidencememo
python -m venv .venv
source .venv/bin/activate     # On SIFT (Linux)
pip install -e .[dev]
pytest                         # smoke tests pass without Volatility installed
evidencememo investigate /cases/example.dmp --hypothesis "ransomware staging"
```

## Files

```
src/evidencememo/
├── __init__.py            public API
├── cli.py                 typer entrypoint
├── investigator.py        investigation loop + self-correction
├── volatility.py          async subprocess wrapper for Volatility 3
└── memo.py                Finding Memo markdown renderer
skills/sift-forensics/
└── SKILL.md               Claude Code skill — the FIXED workflow
tests/
└── test_memo.py           triage + memo rendering smoke tests
pyproject.toml             all deps pinned exact (no >= / ~=)
```

## License

BSD-3-Clause.

## Built by

[Masoud Masoori](https://github.com/Masoud-Masoori) — MAS-AI Technologies Inc.
Engineering partner: Claude Opus 4.7.
