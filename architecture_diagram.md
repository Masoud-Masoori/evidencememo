# EvidenceMemo — Architecture

```
                          ┌──────────────────────────────────┐
                          │   Operator (digital forensics IR) │
                          │                                    │
                          │   evidencememo investigate <dump>  │
                          │   --hypothesis "Cobalt Strike..."  │
                          └──────────────┬───────────────────┘
                                         │
                          ┌──────────────▼──────────────────┐
                          │   typer CLI (src/.../cli.py)     │
                          └──────────────┬──────────────────┘
                                         │
                          ┌──────────────▼──────────────────┐
                          │   investigator.investigate()     │
                          │                                  │
                          │   [Claude Code skill loaded from │
                          │    skills/sift-forensics/SKILL.md│
                          │    governs the WORKFLOW]         │
                          └──────────────┬──────────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              ▼                          ▼                          ▼
  ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
  │  STEP 1               │   │ STEP 2 ★ REQUIRED ★  │   │  STEP 3               │
  │  Profile detection    │   │ Self-correction loop  │   │  Process triage       │
  │                       │   │                       │   │                       │
  │  vol -f <dump>        │   │ If pslist garbage     │   │  Flag typosquats,     │
  │   windows.info        │   │ → retry next profile  │   │  orphaned svchost,    │
  │   linux.info          │   │ → log reasoning       │   │  weird paths           │
  └──────────┬───────────┘   └──────────┬───────────┘   └──────────┬───────────┘
             │                          │                          │
             └──────────────────────────┼──────────────────────────┘
                                        │
              ┌─────────────────────────┼──────────────────────────┐
              ▼                         ▼                          ▼
  ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
  │ Volatility 3          │   │ Volatility 3          │   │ Volatility 3          │
  │  async subprocess     │   │  async subprocess     │   │  async subprocess     │
  │  (volatility.py)      │   │  (volatility.py)      │   │  (volatility.py)      │
  └──────────────────────┘   └──────────────────────┘   └──────────────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │ StreamingVolatility output │
                          │ → VolatilityResult         │
                          │  (rows, looks_valid,       │
                          │   failure_reason)          │
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────────┐
                          │   investigation_log.jsonl      │
                          │   (every step: ts, plugin,     │
                          │    profile, looks_valid,        │
                          │    failure_reason, reasoning,   │
                          │    rows_count)                  │
                          └─────────────┬─────────────────┘
                                        │
                          ┌─────────────▼─────────────────┐
                          │   memo.render() → markdown      │
                          │                                 │
                          │   Finding Memo with Evidence    │
                          │   triple per finding:           │
                          │   • plugin (e.g. windows.pslist)│
                          │   • offset (e.g. 0x82345f60)    │
                          │   • extract (1-line excerpt)    │
                          └─────────────┬─────────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────────┐
                          │   finding-memo.md             │
                          │   investigation-log.jsonl     │
                          │   (the audit trail judges      │
                          │    score "Audit Trail Quality" │
                          │    on)                         │
                          └───────────────────────────────┘
```

## Component table

| Component | Responsibility | File |
|---|---|---|
| Claude Code skill | Workflow contract (FIXED workflow, banned outputs, self-correction rule) | `skills/sift-forensics/SKILL.md` |
| typer CLI | `evidencememo investigate <dump>` entry | `src/evidencememo/cli.py` |
| investigator | Investigation loop with self-correction | `src/evidencememo/investigator.py` |
| volatility wrapper | Async subprocess + output heuristic validation | `src/evidencememo/volatility.py` |
| memo renderer | Finding Memo markdown with Evidence citations | `src/evidencememo/memo.py` |

## The self-correction beat (FIND EVIL rules-required)

The demo video MUST show one self-correction sequence. Here's where it happens:

1. `vol windows.info` returns multiple candidate profiles
2. Agent picks profile A → `vol windows.pslist`
3. Output has 0 rows / non-numeric PIDs → `looks_valid = False`
4. **Agent reasons** (`investigator._run_with_self_correction()`): "Profile A failed pslist validation, trying profile B"
5. Retry with profile B → sensible process list
6. Adopt profile B for the rest of the investigation

The reasoning, retry, and adoption are all captured in `investigation-log.jsonl` so the audit trail is reviewable.

## Required tech stack — confirmed present

- **Claude Code** OR **OpenClaw** — we use Claude Code (skill at `skills/sift-forensics/SKILL.md`)
- **SIFT Workstation** — the Ubuntu-based digital forensics distro that ships Volatility 3
- **Volatility 3** (pinned `volatility3==2.7.0` in `pyproject.toml`)
- **Protocol SIFT extension** — our skill is the new IR capability

## Audit Trail Quality (judging criterion mapped)

| Judging concern | Our artifact |
|---|---|
| Every claim cited | Evidence triple (plugin + offset + extract) per finding |
| Reasoning visible | `investigation-log.jsonl` captures every step's reasoning field |
| Self-correction recorded | log marks `self_corrections: N` + each retry step |
| Accuracy self-assessment | Final memo includes notes for manual verification |
