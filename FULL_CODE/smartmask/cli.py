"""CLI: python -m smartmask.cli --backend sqlite --role support "SELECT * FROM cards LIMIT 3" """

import argparse
import sys

from . import config
from .adapters import PostgresAdapter, SqliteAdapter
from .engine import MaskingEngine, PolicyViolation
from .policy import Policy
from .store import MetaStore


def main(argv=None):
    p = argparse.ArgumentParser(prog="smartmask")
    p.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    p.add_argument("--role", default="support")
    p.add_argument("--scan", action="store_true", help="scan the schema and print tags")
    p.add_argument("--show-sql", action="store_true", help="print the rewritten SQL")
    p.add_argument("sql", nargs="?")
    a = p.parse_args(argv)
    ad = SqliteAdapter(config.SQLITE_PATH) if a.backend == "sqlite" else PostgresAdapter(config.PG_DSN)
    eng = MaskingEngine(ad, MetaStore(config.META_PATH), Policy(), config.SALT)
    if a.scan or not eng.store.load_tags(eng.db_key):
        for t in eng.run_scan():
            print(f"{t.table}.{t.column:<16} {t.entity:<11} {t.tag:<24} confidence={t.confidence}")
        if a.scan:
            return 0
    if not a.sql:
        p.error("provide a SQL query")
    try:
        r = eng.execute(a.role, a.sql, user="cli")
    except PolicyViolation as e:
        print(f"DENIED: {e}", file=sys.stderr)
        return 2
    if a.show_sql:
        print("--", r.rewritten_sql)
    print(" | ".join(r.columns))
    for row in r.rows:
        print(" | ".join("NULL" if v is None else str(v) for v in row))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
