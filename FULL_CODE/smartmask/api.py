"""Small FastAPI surface (Postman-friendly). Run: uvicorn smartmask.api:app --port 8000"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import config
from .adapters import PostgresAdapter, SqliteAdapter
from .engine import MaskingEngine, PolicyViolation
from .policy import Policy
from .store import MetaStore

app = FastAPI(title="SmartMask", description="Dynamic, role-based PII masking at query time. Demo data is synthetic.")
_store, _policy = MetaStore(config.META_PATH), Policy()
_engines: dict[str, MaskingEngine] = {}


def engine(backend: str) -> MaskingEngine:
    if backend not in _engines:
        if backend == "sqlite":
            ad = SqliteAdapter(config.SQLITE_PATH)
        elif backend == "postgres":
            ad = PostgresAdapter(config.PG_DSN)
        else:
            raise HTTPException(404, "backend must be 'sqlite' or 'postgres'")
        eng = MaskingEngine(ad, _store, _policy, config.SALT)
        if not _store.load_tags(eng.db_key):
            eng.run_scan()
        _engines[backend] = eng
    return _engines[backend]


class QueryIn(BaseModel):
    backend: str = "sqlite"
    role: str
    sql: str
    user: str = "api-user"


@app.post("/scan/{backend}")
def scan_endpoint(backend: str):
    tags = engine(backend).run_scan()
    return [t.as_dict() for t in tags]


@app.get("/tags/{backend}")
def tags_endpoint(backend: str):
    return [t.as_dict() for t in engine(backend).store.load_tags(engine(backend).db_key).values()]


@app.get("/policy")
def policy_endpoint():
    return _policy.roles


@app.post("/query")
def query_endpoint(q: QueryIn):
    eng = engine(q.backend)
    try:
        r = eng.execute(q.role, q.sql, q.user)
    except KeyError as e:
        raise HTTPException(400, str(e))
    except PolicyViolation as e:
        raise HTTPException(403, str(e))
    return {
        "role": r.role,
        "columns": r.columns,
        "rows": r.rows,
        "masked": r.masked,
        "rewritten_sql": r.rewritten_sql,
        "truncated": r.truncated,
    }
