"""EvidenceMemo — autonomous forensic investigator on SIFT.

Built for the FIND EVIL hackathon. Extends SANS Protocol SIFT with a
Claude Code-driven investigation loop that self-corrects across Volatility
profile detection.

Top-level API:
    from evidencememo import investigate

    memo = investigate(
        evidence_path="/cases/case-001/memory.dmp",
        hypothesis="Possible Cobalt Strike beacon",
    )
"""

from evidencememo.investigator import investigate
from evidencememo.memo import FindingMemo

__version__ = "0.1.0"
__all__ = ["investigate", "FindingMemo"]
