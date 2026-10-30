import os

SQLITE_PATH = os.environ.get("SMARTMASK_SQLITE", "data/bank.db")
PG_DSN = os.environ.get("SMARTMASK_PG_DSN", "host=localhost port=5433 dbname=postgres user=smartmask_app")
SALT = os.environ.get("SMARTMASK_SALT", "demo-salt-change-me")
META_PATH = os.environ.get("SMARTMASK_META", "data/smartmask_meta.db")
LLM_MODEL = os.environ.get("SMARTMASK_LLM_MODEL", "claude-haiku-5-5")  # optional AI assist; needs ANTHROPIC_API_KEY
LLM_TIMEOUT = int(os.environ.get("SMARTMASK_LLM_TIMEOUT", "20"))
LLM_URL = os.environ.get("SMARTMASK_LLM_URL", "https://api.anthropic.com/v1/messages")
LLM_MAX_TOKENS = int(os.environ.get("SMARTMASK_LLM_MAX_TOKENS", "200"))
LLM_TEMPERATURE = float(os.environ.get("SMARTMASK_LLM_TEMPERATURE", "0"))
AI_MIN_PROB = float(os.environ.get("SMARTMASK_AI_MIN_PROB", "0.6"))  # local-model answers below this count as "no opinion"
AI_AUTO_MIN_PROB = float(os.environ.get("SMARTMASK_AI_AUTO_MIN_PROB", "0.85"))  # confidence needed for automatic additions
