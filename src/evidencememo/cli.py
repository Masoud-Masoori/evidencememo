"""CLI: `evidencememo investigate path/to/dump.mem --hypothesis "..."`."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer

from evidencememo.investigator import investigate

app = typer.Typer(no_args_is_help=True, help="Autonomous forensic investigator on SIFT.")


@app.command()
def cli_investigate(
    evidence_path: str = typer.Argument(..., help="Path to memory dump (.mem / .raw / .dmp)"),
    hypothesis: str = typer.Option(..., "--hypothesis", "-h", help="One-sentence hypothesis"),
    out_memo: Path = typer.Option(Path("finding-memo.md"), "--out-memo", help="Where to write the memo"),
    out_log: Path = typer.Option(Path("investigation-log.jsonl"), "--out-log", help="Where to write the JSONL execution log"),
) -> None:
    memo, log = asyncio.run(investigate(evidence_path, hypothesis))
    out_memo.write_text(memo.to_markdown(), encoding="utf-8")

    import json
    with out_log.open("w", encoding="utf-8") as f:
        for step in log.steps:
            f.write(json.dumps(step.__dict__) + "\n")

    typer.echo(f"wrote {out_memo}")
    typer.echo(f"wrote {out_log}")
    typer.echo(f"steps={len(log.steps)} self_corrections={log.self_corrections} findings={len(memo.findings)}")


if __name__ == "__main__":
    app()
