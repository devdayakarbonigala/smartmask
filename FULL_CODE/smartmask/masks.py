"""Masking expressions as SQL, so masking happens inside the database engine."""

from __future__ import annotations

import sqlglot
from sqlglot import exp

from .scrub import RULES

SALT_TOKEN = "__SALT__"
C = "__col__"
LAST4 = f"SUBSTR(CAST({C} AS TEXT), LENGTH(CAST({C} AS TEXT)) - 3)"


def _partial(entity: str, dialect: str) -> str:
    t = f"CAST({C} AS TEXT)"
    if entity == "CARD":
        return (
            f"CASE WHEN LENGTH({t}) = 19 THEN SUBSTR({t}, 1, 4) || '-XXXX-XXXX-' || SUBSTR({t}, 16, 4) ELSE '****' || {LAST4} END"
        )
    if entity == "SSN":
        return f"'XXX-XX-' || {LAST4}"
    if entity == "AADHAAR":
        return f"'XXXX XXXX ' || {LAST4}"
    if entity == "EMAIL":
        pos = "STRPOS" if dialect == "postgres" else "INSTR"
        return f"SUBSTR({t}, 1, 1) || '***' || SUBSTR({t}, {pos}({t}, '@'))"
    if entity == "DOB":
        return f"SUBSTR({t}, 1, 4) || '-XX-XX'"
    if entity == "NAME":
        return f"SUBSTR({t}, 1, 1) || '***'"
    if entity == "ADDRESS":
        return f"SUBSTR({t}, 1, 3) || '***'"
    if entity in ("PAN", "PHONE"):
        return f"'******' || {LAST4}"
    return f"'****' || {LAST4}"  # ACCOUNT_NO and any other entity


def _hash(dialect: str) -> str:
    if dialect == "postgres":
        return f"SUBSTR(ENCODE(SHA256(CONVERT_TO('{SALT_TOKEN}' || CAST({C} AS TEXT), 'UTF8')), 'hex'), 1, 16)"
    return f"SM_SHA16('{SALT_TOKEN}' || CAST({C} AS TEXT))"


def _scrub_postgres(column: exp.Column) -> exp.Expression:
    """Nested REGEXP_REPLACE(..., 'g') calls built from the shared rule list in scrub.py."""
    node: exp.Expression = exp.Cast(this=column.copy(), to=exp.DataType.build("text"))
    for pattern, repl in RULES:
        node = exp.Anonymous(
            this="REGEXP_REPLACE",
            expressions=[node, exp.Literal.string(pattern), exp.Literal.string(repl), exp.Literal.string("g")],
        )
    return node


def mask_expression(mask: str, entity: str, numeric: bool, dialect: str, column: exp.Column) -> exp.Expression | None:
    """Build the masked replacement for `column`. Returns None when no masking is needed."""
    if mask == "none":
        return None
    if mask == "scrub":
        if dialect == "postgres":
            return _scrub_postgres(column)
        return exp.Anonymous(this="SM_SCRUB", expressions=[exp.Cast(this=column.copy(), to=exp.DataType.build("text"))])
    if mask == "redact":
        snippet = "CAST(NULL AS DECIMAL)" if numeric else "'[REDACTED]'"
    elif mask == "hash":
        snippet = _hash(dialect)
    elif mask == "partial":
        if numeric and entity == "BALANCE":
            snippet = "CAST(NULL AS DECIMAL)"
        else:
            snippet = _partial(entity, dialect)
    else:
        raise ValueError(f"Unknown mask type: {mask}")
    node = sqlglot.parse_one(snippet, read=dialect)

    def sub(n):
        if isinstance(n, exp.Column) and n.name.lower() == C:
            return column.copy()
        return n

    out = node.transform(sub)
    return exp.Paren(this=out) if not isinstance(out, (exp.Column, exp.Null, exp.Literal)) else out
