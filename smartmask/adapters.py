"""Database adapters. Both open READ-ONLY connections, so the raw tables cannot change."""
from __future__ import annotations

import hashlib
import sqlite3
from typing import Any


class Adapter:
    name = "base"
    dialect = "base"

    def schema(self) -> dict[str, dict[str, str]]: ...
    def sample(self, table: str, column: str, n: int) -> list[Any]: ...
    def execute(self, sql: str, max_rows: int = 500) -> tuple[list[str], list[tuple], bool]: ...


def _sha16(text):
    if text is None:
        return None
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()[:16]


class SqliteAdapter(Adapter):
    name = "SQLite"
    dialect = "sqlite"

    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        self.conn.create_function("sm_sha16", 1, _sha16, deterministic=True)

    def schema(self):
        out: dict[str, dict[str, str]] = {}
        tables = [r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        for t in tables:
            out[t.lower()] = {r[1].lower(): (r[2] or "TEXT") for r in self.conn.execute(f'PRAGMA table_info("{t}")')}
        return out

    def sample(self, table, column, n):
        cur = self.conn.execute(f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL LIMIT {int(n)}')
        return [r[0] for r in cur.fetchall()]

    def execute(self, sql, max_rows=500):
        cur = self.conn.execute(sql)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchmany(max_rows + 1)
        return cols, [tuple(r) for r in rows[:max_rows]], len(rows) > max_rows

    def raw_execute_for_test(self, sql):
        return self.conn.execute(sql)


class PostgresAdapter(Adapter):
    name = "PostgreSQL"
    dialect = "postgres"

    def __init__(self, dsn: str):
        import psycopg
        self.conn = psycopg.connect(dsn, autocommit=True, options="-c default_transaction_read_only=on")

    def schema(self):
        out: dict[str, dict[str, str]] = {}
        with self.conn.cursor() as cur:
            cur.execute("""SELECT table_name, column_name, data_type FROM information_schema.columns
                           WHERE table_schema='public' ORDER BY table_name, ordinal_position""")
            for t, c, d in cur.fetchall():
                out.setdefault(t.lower(), {})[c.lower()] = d
        return out

    def sample(self, table, column, n):
        with self.conn.cursor() as cur:
            cur.execute(f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL LIMIT {int(n)}')
            return [r[0] for r in cur.fetchall()]

    def execute(self, sql, max_rows=500):
        with self.conn.cursor() as cur:
            cur.execute(sql)
            cols = [d.name for d in cur.description]
            rows = cur.fetchmany(max_rows + 1)
            return cols, [tuple(r) for r in rows[:max_rows]], len(rows) > max_rows

    def raw_execute_for_test(self, sql):
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur
