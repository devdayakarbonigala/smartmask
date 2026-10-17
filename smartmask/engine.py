"""Dynamic masking engine: rewrites a SELECT so the DATABASE applies the mask for the caller's role.

Rules enforced:
  * exactly one statement, and it must be a SELECT (or UNION of SELECTs)
  * only known SQL functions (unknown or system functions are rejected)
  * only tables that exist in the scanned schema (system catalogs are not reachable)
  * a protected column may be PROJECTED (it is replaced by its masked expression)
  * a protected column may NOT be used in WHERE / JOIN / HAVING / ORDER BY / GROUP BY for a masked role,
    because that would let a user probe raw values ("WHERE card_number LIKE '4111%'")
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify
from sqlglot.optimizer.scope import traverse_scope

from .masks import SALT_TOKEN, mask_expression
from .policy import Policy
from .scanner import is_numeric_type, scan
from .store import MetaStore


class PolicyViolation(Exception):
    pass


@dataclass
class QueryResult:
    role: str
    original_sql: str
    rewritten_sql: str
    columns: list[str]
    rows: list[tuple]
    truncated: bool
    masked: list[dict] = field(default_factory=list)
    elapsed_ms: float = 0.0


class MaskingEngine:
    def __init__(self, adapter, store: MetaStore, policy: Policy, salt: str = "demo-salt-change-me"):
        self.adapter, self.store, self.policy, self.salt = adapter, store, policy, salt
        self.db_key = adapter.name.lower()
        self._schema = None

    # ---- scanning -------------------------------------------------------------------------
    def run_scan(self, sample_size: int = 200):
        tags = scan(self.adapter, sample_size)
        self.store.save_tags(self.db_key, tags)
        return tags

    def schema(self):
        if self._schema is None:
            self._schema = self.adapter.schema()
        return self._schema

    # ---- rewriting ------------------------------------------------------------------------
    def rewrite(self, sql: str, role: str) -> tuple[str, list[dict]]:
        dialect = self.adapter.dialect
        try:
            statements = [s for s in sqlglot.parse(sql, read=dialect) if s is not None]
        except SqlglotError as e:
            raise PolicyViolation(f"SQL could not be parsed: {str(e).splitlines()[0]}")
        if len(statements) != 1:
            raise PolicyViolation("Exactly one statement is allowed.")
        tree = statements[0]
        if not isinstance(tree, (exp.Select, exp.Union)):
            raise PolicyViolation("Only SELECT statements are allowed.")
        if tree.find(exp.Anonymous):
            fn = tree.find(exp.Anonymous).name
            raise PolicyViolation(f"Function '{fn}' is not on the allow-list.")
        if tree.find(exp.Into):
            raise PolicyViolation("SELECT ... INTO is not allowed.")

        schema = self.schema()
        sg_schema = {t: {c: d for c, d in cols.items()} for t, cols in schema.items()}
        try:
            tree = qualify(tree, schema=sg_schema, dialect=dialect, quote_identifiers=False,
                           identify=False, validate_qualify_columns=True)
        except SqlglotError as e:
            raise PolicyViolation(f"Query rejected: {str(e).splitlines()[0]}")

        tagmap = self.store.load_tags(self.db_key)
        replacements: list[tuple[exp.Column, exp.Expression]] = []
        masked: list[dict] = []

        scopes = traverse_scope(tree)
        for scope in scopes:
            for src in scope.sources.values():
                if isinstance(src, exp.Table) and src.name.lower() not in schema:
                    raise PolicyViolation(f"Table '{src.name}' is not available.")
            for col in list(scope.columns) + list(scope.external_columns):
                base = self._base_table(scope, col)
                if base is None:
                    continue
                tag = tagmap.get((base, col.name.lower()))
                if not tag:
                    continue
                mask = self.policy.mask_for(role, tag.entity)
                if mask == "none":
                    continue
                if not self._in_projection(col):
                    raise PolicyViolation(
                        f"Role '{role}' may not filter, join, group or sort on protected column "
                        f"{base}.{col.name} ({tag.tag}).")
                numeric = is_numeric_type(schema[base].get(col.name.lower(), ""))
                repl = mask_expression(mask, tag.entity, numeric, dialect, col)
                if repl is not None:
                    replacements.append((col, repl))
                    masked.append({"table": base, "column": col.name.lower(), "entity": tag.entity,
                                   "tag": tag.tag, "mask": mask})
        for col, repl in replacements:
            col.replace(repl)
        # de-duplicate the report
        seen, uniq = set(), []
        for m in masked:
            k = (m["table"], m["column"], m["mask"])
            if k not in seen:
                seen.add(k)
                uniq.append(m)
        return tree.sql(dialect=dialect), uniq

    @staticmethod
    def _base_table(scope, col: exp.Column):
        s = scope
        while s is not None:
            src = s.sources.get(col.table)
            if src is not None:
                return src.name.lower() if isinstance(src, exp.Table) else None
            s = s.parent
        return None

    @staticmethod
    def _in_projection(col: exp.Column) -> bool:
        select = col.find_ancestor(exp.Select)
        if select is None:
            return False
        cur = col
        while cur.parent is not select:
            cur = cur.parent
            if cur is None:
                return False
        return cur.arg_key == "expressions"

    # ---- execution ------------------------------------------------------------------------
    def execute(self, role: str, sql: str, user: str = "demo") -> QueryResult:
        t0 = time.perf_counter()
        try:
            rewritten, masked = self.rewrite(sql, role)
        except PolicyViolation as e:
            self.store.audit(self.db_key, user, role, "DENIED", sql, "", [], 0, str(e))
            raise
        runnable = rewritten.replace(SALT_TOKEN, self.salt)
        try:
            cols, rows, truncated = self.adapter.execute(runnable)
        except Exception as e:  # database-side error (bad cast, timeout, ...)
            msg = str(e).splitlines()[0]
            self.store.audit(self.db_key, user, role, "ERROR", sql, rewritten, masked, 0, msg)
            raise PolicyViolation(f"Database error: {msg}")
        self.store.audit(self.db_key, user, role, "OK", sql, rewritten, masked, len(rows))
        return QueryResult(role, sql, rewritten, cols, rows, truncated, masked, (time.perf_counter() - t0) * 1000)
