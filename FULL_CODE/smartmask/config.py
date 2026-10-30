import os

SQLITE_PATH = os.environ.get("SMARTMASK_SQLITE", "data/bank.db")
PG_DSN = os.environ.get("SMARTMASK_PG_DSN", "host=localhost port=5433 dbname=postgres user=smartmask_app")
SALT = os.environ.get("SMARTMASK_SALT", "demo-salt-change-me")
META_PATH = os.environ.get("SMARTMASK_META", "data/smartmask_meta.db")
LLM_MODEL = os.environ.get("SMARTMASK_LLM_MODEL", "claude-haiku-5-5")  # optional AI assist; needs ANTHROPIC_API_KEY
LLM_TIMEOUT = int(os.environ.get("SMARTMASK_LLM_TIMEOUT", "20"))
