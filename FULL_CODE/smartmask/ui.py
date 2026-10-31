"""Presentation helpers for the Streamlit demo. No database or masking logic lives here."""

from __future__ import annotations

from collections import Counter
from html import escape

import pandas as pd

INK, PAPER, RULE = "#1F2420", "#EFEAE0", "#B8AE98"
# One earth tone per mask type, so a masked cell can be read at a glance.
MASK_STYLE = {
    "none": ("#F8F5EE", INK, "raw"),
    "partial": ("#E3C98B", INK, "partial"),
    "hash": ("#B9C7B0", INK, "hash token"),
    "scrub": ("#DDB59F", INK, "scrubbed text"),
    "redact": (INK, PAPER, "redacted"),
}
MASK_ORDER = ["none", "partial", "hash", "scrub", "redact"]

CSS = f"""
<style>
.block-container {{ padding-top: 2.2rem; max-width: 1180px; }}
h1, h2, h3 {{ letter-spacing: 0.01em; }}
.sm-title {{ font-family: Georgia, serif; font-size: 3rem; line-height: 1.05; margin: 0 0 .2rem 0; color: {INK}; }}
.sm-rule {{ border: 0; border-top: 3px double {INK}; margin: .4rem 0 .8rem 0; }}
.sm-sub {{ font-size: 1.05rem; color: {INK}; margin-bottom: 1rem; }}
.sm-chip {{ display: inline-block; padding: .05rem .55rem; margin: 0 .35rem .25rem 0; font-size: .82rem; border: 1px solid {INK}; }}
.sm-ledger {{ display: flex; height: 22px; border: 1px solid {INK}; margin: .15rem 0 .1rem 0; }}
.sm-ledger span {{ display: block; height: 100%; border-right: 1px solid {PAPER}; }}
.sm-label {{ font-size: .78rem; letter-spacing: .12em; text-transform: uppercase; color: {INK}; margin-top: .7rem; }}
.sm-who {{ border: 1px solid {INK}; padding: .5rem .7rem; margin-bottom: .6rem; }}
.sm-who b {{ display: block; font-size: 1.05rem; }}
.sm-spec {{ width: 100%; border-collapse: collapse; font-family: Menlo, Consolas, monospace; font-size: .9rem; }}
.sm-spec th {{ text-align: left; font-weight: 400; font-size: .72rem; letter-spacing: .12em; text-transform: uppercase;
  border-bottom: 1px solid {INK}; padding: .35rem .5rem; }}
.sm-spec td {{ padding: .45rem .5rem; border-bottom: 1px dotted {RULE}; }}
</style>
"""

SPECIMEN = [
    ("admin", "Asha Rao", "+91-9876501234", "1990-04-12", "raw"),
    ("support", "A***", "******1234", "1990-XX-XX", "partial"),
    ("analyst", "9f2c41d07b3ae618", "6c0e92af4d1b7753", "[REDACTED]", "hash"),
]


def chip(kind: str) -> str:
    bg, fg, label = MASK_STYLE[kind]
    return f'<span class="sm-chip" style="background:{bg};color:{fg}">{escape(label)}</span>'


def legend() -> str:
    return "".join(chip(k) for k in MASK_ORDER)


def style_masked(df: pd.DataFrame, masks: dict[str, str]):
    """Colour each masked column by its mask type so a reviewer can see what the role was given."""

    def paint(col: pd.Series):
        kind = masks.get(str(col.name).lower())
        if kind not in MASK_STYLE:
            return [""] * len(col)
        bg, fg, _ = MASK_STYLE[kind]
        return [f"background-color:{bg};color:{fg}"] * len(col)

    return df.style.apply(paint, axis=0)


def exposure(tags, policy) -> dict[str, Counter]:
    """For each role, how many tagged columns it receives raw, partial, hashed, scrubbed or redacted."""
    entities = [t.entity for t in tags.values() if t.entity and t.entity != "NONE"]
    return {role: Counter(policy.mask_for(role, e) for e in entities) for role in policy.role_names()}


def ledger_html(counts: dict[str, Counter]) -> str:
    rows = []
    for role, c in counts.items():
        total = sum(c.values()) or 1
        segs = "".join(
            f'<span style="width:{100 * c[k] / total:.2f}%;background:{MASK_STYLE[k][0]}" title="{c[k]} {MASK_STYLE[k][2]}"></span>'
            for k in MASK_ORDER
            if c[k]
        )
        detail = ", ".join(f"{c[k]} {MASK_STYLE[k][2]}" for k in MASK_ORDER if c[k])
        rows.append(
            f'<div class="sm-label">{escape(role)}</div><div class="sm-ledger">{segs}</div><small>{escape(detail)}</small>'
        )
    return "".join(rows)


def specimen_html() -> str:
    body = "".join(
        f"<tr><td>{escape(r)}</td><td>{escape(n)}</td><td>{escape(p)}</td><td>{escape(d)}</td></tr>" for r, n, p, d, _ in SPECIMEN
    )
    return f'<table class="sm-spec"><tr><th>role</th><th>name</th><th>phone</th><th>born</th></tr>{body}</table>'


def title_html() -> str:
    return (
        '<div class="sm-title">SmartMask</div><hr class="sm-rule">'
        '<div class="sm-sub">Role-based data masking, applied inside the query. '
        "Stored tables are never modified.</div>"
    )
