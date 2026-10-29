"""Metadata store (tags, manual overrides, audit log).

Deliberately a SEPARATE SQLite file: the protected database is never written to.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .scanner import TAGS, ColumnTag


class MetaStore:
    def __init__(self, path: str = "data/smartmask_meta.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS tags(db_key TEXT, tbl TEXT, col TEXT, data_type TEXT, entity TEXT, tag TEXT,
            confidence REAL, name_hit INT, value_ratio REAL, source TEXT, PRIMARY KEY(db_key, tbl, col));
        CREATE TABLE IF NOT EXISTS overrides(db_key TEXT, tbl TEXT, col TEXT, entity TEXT, PRIMARY KEY(db_key, tbl, col));
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, db_key TEXT, user TEXT,
            role TEXT, status TEXT, original_sql TEXT, rewritten_sql TEXT, masked_columns TEXT, row_count INT, detail TEXT);
        """)

    def save_tags(self, db_key: str, tags: list[ColumnTag]):
        self.conn.execute("DELETE FROM tags WHERE db_key=?", (db_key,))
        for t in tags:
            self.conn.execute(
                "INSERT INTO tags VALUES (?,?,?,?,?,?,?,?,?,?)",
                (db_key, t.table, t.column, t.data_type, t.entity, t.tag, t.confidence, int(t.name_hit), t.value_ratio, t.source),
            )
        self.conn.commit()

    def set_override(self, db_key, table, column, entity):
        """entity = one of the known entities, or 'NONE' to force a column to be untagged."""
        self.conn.execute("INSERT OR REPLACE INTO overrides VALUES (?,?,?,?)", (db_key, table.lower(), column.lower(), entity))
        self.conn.commit()

    def load_tags(self, db_key: str) -> dict[tuple[str, str], ColumnTag]:
        out = {}
        for r in self.conn.execute(
            "SELECT tbl,col,data_type,entity,tag,confidence,name_hit,value_ratio,source FROM tags WHERE db_key=?", (db_key,)
        ):
            out[(r[0].lower(), r[1].lower())] = ColumnTag(r[0], r[1], r[2], r[3], r[4], r[5], bool(r[6]), r[7], r[8])
        for tbl, col, entity in self.conn.execute("SELECT tbl,col,entity FROM overrides WHERE db_key=?", (db_key,)):
            if entity == "NONE":
                out.pop((tbl, col), None)
            elif entity in TAGS:
                out[(tbl, col)] = ColumnTag(tbl, col, "", entity, TAGS[entity], 1.0, True, 1.0, "override")
        return out

    def audit(self, db_key, user, role, status, original_sql, rewritten_sql, masked_columns, row_count, detail=""):
        self.conn.execute(
            "INSERT INTO audit_log(ts,db_key,user,role,status,original_sql,rewritten_sql,masked_columns,row_count,detail) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                db_key,
                user,
                role,
                status,
                original_sql,
                rewritten_sql,
                json.dumps(masked_columns),
                row_count,
                detail,
            ),
        )
        self.conn.commit()

    def audit_rows(self, limit=200):
        cur = self.conn.execute(
            "SELECT ts,user,role,status,original_sql,masked_columns,row_count,detail FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()
