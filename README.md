# SmartMask: Smart Data Masking System for PII Protection

Team METIS (TEAM-000682), Talent AP Mega Hackathon 2026. Problem 11, BFSI (B1).

SmartMask connects to a database, scans the schema and a row sample to tag sensitive columns, and masks them
**at query time** for the role that is asking. The stored tables are never modified.

| Role | `card_number` | `ssn` | `balance` | free text (notes, narration, JSON) |
|---|---|---|---|---|
| admin | raw | raw | raw | raw |
| support | first 4 and last 4 digits | last 4 digits | redacted | identifiers replaced with `[PAN]`, `[PHONE]`, `[EMAIL]` ... |
| analyst | salted hash token | salted hash token | redacted | same replacement as support |

## What it does

* **Scanner** (`smartmask/scanner.py`, `checks.py`, `scrub.py`): column-name hints plus value checks (regex, Luhn,
  Verhoeff). Tags `PII_HIGH`, `PII_MEDIUM` and `FINANCIAL_CONFIDENTIAL`. Text columns that hide identifiers inside
  sentences or JSON are tagged `FREETEXT`.
* **Masking engine** (`engine.py`, `masks.py`, `adapters.py`): the query is parsed with `sqlglot`, protected columns in
  the projection are replaced by masking SQL in the backend's own dialect (redaction, partial masking, hashing,
  free-text scrubbing). The database does the masking, so raw values never leave it for a restricted role.
  Backends: PostgreSQL and SQLite, with identical output (checked on every row of the organisers' dataset).
* **Interfaces**: Streamlit demo (`app.py`), CLI (`smartmask/cli.py`), FastAPI (`smartmask/api.py`).

Safety rules in the engine:

* One statement, `SELECT` only. Unknown functions and tables outside the scanned schema are rejected.
* A role that sees a masked value may not filter, join, group or sort on that column (no `WHERE card_number LIKE '4111%'`).
* Read-only connections (SQLite `mode=ro`; PostgreSQL read-only transaction and a SELECT-only user).
* A column tagged with an entity the role has no rule for is redacted.
* **Fail closed**: if the schema scan fails, the query is refused rather than served unmasked.
* Tags, overrides and the audit log live in a separate metadata file, never in the protected database.

## How to run

Python 3.11 or newer.

```bash
cd FULL_CODE
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env && set -a && source .env && set +a

# Option A: synthetic demo data
python -m smartmask.seed                    # creates data/bank.db (add SMARTMASK_PG_ADMIN_DSN to load PostgreSQL too)

# Option B: the organisers' Saffron Bank pack
export SMARTMASK_SQLITE=/path/to/saffron_bank.db
# PostgreSQL: start the pack's docker-compose database and set SMARTMASK_PG_DSN to a read-only user

streamlit run app.py                        # demo UI (choose backend and role in the sidebar)
python -m smartmask.cli --role support --show-sql "SELECT card_number FROM cards LIMIT 3"
uvicorn smartmask.api:app --port 8000       # API docs at /docs
```

## How to run the tests

```bash
cd FULL_CODE
python -m pytest -q tests                   # creates data/bank.db on first run; SQLite only
# with PostgreSQL available (set SMARTMASK_PG_ADMIN_DSN and SMARTMASK_PG_DSN, run python -m smartmask.seed first): also runs the PostgreSQL variants
ruff check . && ruff format --check .
python -m smartmask.benchmark               # scanner accuracy on a synthetic labelled schema
python -m smartmask.benchmark_saffron path/to/saffron_bank.db
```

## Architecture

```
query + role -> parse and qualify (sqlglot) -> deny probing / non-SELECT -> replace protected columns
             -> run on read-only connection (PostgreSQL or SQLite) -> masked rows + audit entry
scan:  schema + sample -> name hints + validators -> tags (metadata store, keyed by backend and schema)
policy: smartmask/policy.json maps role x entity -> mask (none, partial, hash, redact, scrub)
```

## Measured results

| Check | Result |
|---|---|
| Saffron pack, 120 columns, 35 sensitive columns labelled by us | 35 of 35 found, no false positives |
| Synthetic labelled schema, 63 columns | precision 96%, recall 80%, entity accuracy 100% |
| SQLite vs PostgreSQL output on the Saffron pack (129,260 rows, support and analyst roles) | identical on all tables |

Both benchmarks were labelled by the same people who tuned the scanner, so they are regression checks and not
independent accuracy claims.

## AI Assist (optional second opinion)

The masking itself is deterministic SQL, with no AI in the data path. The **AI Assist** tab adds a review step for
column tagging, built so that AI can suggest but never decide:

* Three signals vote on each column: the rules, a small local model, and an optional language model.
* The local model (character n-grams of the column name plus statistics of value *shapes*, logistic regression) is
  trained at start-up from synthetic generators only. No organiser data is used for training.
* The language model is off unless `ANTHROPIC_API_KEY` is set. It is asked only where the signals disagree, sees only
  the table and column name, the data type and value shapes (never real values), must answer a strict JSON schema, and
  any timeout or malformed reply is dropped. This path is covered by tests with a fake transport and has not been run
  against the live API.
* A suggestion changes nothing until a person approves it in the tab, which writes a manual override. Hashing and
  redaction stay in SQL and are never done by a model.

Measured on the Saffron SQLite pack (`python -m smartmask.benchmark_ai <saffron_bank.db>`): the local model finds
12 of 27 sensitive non-text columns, all with the right entity, and raises one false suggestion (a date column).
The rules already find all 35 labelled columns there, so on this pack the model adds a check, not recall. It is weak
on names, addresses and balances because their shapes vary. Its use is cryptically named columns with a distinctive
shape (PAN, card, email). The generators were tuned after seeing Saffron results, so treat the numbers as optimistic.

## AI usage

This project was built with the help of an AI coding assistant (Claude). The idea selection, review, testing and
submission are the team's.

## Pre-built and third-party code

SmartMask was written for this hackathon. It uses these open-source libraries (pinned in `FULL_CODE/requirements.txt`):
streamlit, fastapi, uvicorn, sqlglot, faker, psycopg, pandas, scikit-learn (with numpy and scipy). Dev tools: pytest, httpx, ruff. All demo data is
synthetic and generated by `smartmask/seed.py`. The Saffron Bank pack belongs to the organisers and is not included.

## Limitations

* Strict by design: analysts cannot filter on a protected column, even for legitimate analytics.
* Hash tokens use one deployment-wide salt (identical values give identical tokens, so joins work). Set `SMARTMASK_SALT`.
* Free-text scrubbing is rule based. Card numbers are recognised by shape inside SQL (no Luhn check there), so some
  13 to 19 digit reference numbers in free-text columns may also be replaced.
* City, state, pincode and gender are quasi-identifiers and are not masked. Branch contact columns are treated as
  business data. Amount columns (`amount_inr`) are not tagged as sensitive.
* Cryptically named columns with no distinctive value pattern need a manual override.
* MySQL is not supported.
* Not a certified GDPR or HIPAA control.

## License

MIT. See `LICENSE`.
