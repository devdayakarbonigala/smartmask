"""How the local AI signal behaves on the organisers' Saffron Bank pack (the pack is not part of this repository).

    python -m smartmask.benchmark_ai path/to/saffron_bank.db

The model is trained only on synthetic columns generated in ai_assist.py; it has never seen this pack.
The sensitive-column labels are the same ones used in benchmark_saffron.py and were written by the team,
so read the result as a sanity check, not as independent accuracy.
"""

from __future__ import annotations

import json
import sys

from .adapters import SqliteAdapter
from .ai_assist import get_model, review_all
from .benchmark_saffron import SENSITIVE
from .scanner import scan


def run(db_path: str) -> dict:
    ad = SqliteAdapter(db_path)
    rule_tags = {(t.table.lower(), t.column.lower()): t for t in scan(ad)}
    reviews = review_all(ad, rule_tags, get_model())
    key = lambda r: (r.table.lower(), r.column.lower())  # noqa: E731
    labelled = {k: v for k, v in SENSITIVE.items() if v != "FREETEXT"}  # free text is the scrubber's job
    ml_hits = {key(r): r.ml for r in reviews if r.ml}
    tp = [k for k in ml_hits if k in labelled]
    return {
        "columns": len(reviews),
        "sensitive_non_text_labelled": len(labelled),
        "local_model_flagged": len(ml_hits),
        "local_model_correct_columns": len(tp),
        "local_model_correct_entity": sum(1 for k in tp if ml_hits[k] == labelled[k]),
        "local_model_missed": sorted(k for k in labelled if k not in ml_hits),
        "local_model_extra": sorted((k, v) for k, v in ml_hits.items() if k not in labelled),
        "verdicts": {
            v: sum(1 for r in reviews if r.verdict == v) for v in ("agree", "rules only", "suggest", "conflict", "clear")
        },
        "review_queue": [
            f"{r.table}.{r.column}: rules={r.rules} ml={r.ml} ({r.ml_prob}) -> {r.note}" for r in reviews if r.needs_review
        ],
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    print(json.dumps(run(sys.argv[1]), indent=2, default=str))
