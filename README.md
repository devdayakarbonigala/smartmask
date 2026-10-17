# SmartMask

Role-based dynamic data masking for PII. Built for the Talent AP Mega Hackathon, problem statement 11 (BFSI): *Smart Data Masking System for PII Protection*.

SmartMask connects to a database, scans the schema and a row sample to tag sensitive columns, and masks those columns **at query time** according to the role that is asking. The stored tables are never modified.

| Role | `card_number` | `ssn` | `balance` |
|---|---|---|---|
| admin | 4111-1111-1111-1111 | 123-45-6789 | 84250.00 |
| support | 4111-XXXX-XXXX-1111 | XXX-XX-6789 | NULL (shown as [REDACTED]) |
| analyst | salted SHA-256 token | salted SHA-256 token | NULL (shown as [REDACTED]) |

## What is in the box

| Brief requirement | Where |
|---|---|
| Automated PII scanner (regex and rules, tags such as `PII_HIGH`, `FINANCIAL_CONFIDENTIAL`) | `smartmask/scanner.py`, `smartmask/checks.py` |
| Dynamic masking engine, two database backends (PostgreSQL and SQLite), redaction, partial masking, hashing | `smartmask/engine.py`, `smartmask/masks.py`, `smartmask/adapters.py` |
| Interactive demonstration where roles are toggled and underlying tables stay intact | `app.py` (Streamlit), `smartmask/cli.py`, `smartmask/api.py` (FastAPI) |

How it works: the query is parsed with `sqlglot`, columns are resolved to base tables (aliases, joins, CTEs, subqueries, `SELECT *`), and each protected column in the projection is replaced by a masking expression written in the backend's own SQL. The database does the masking, so raw values never leave it for a restricted role.

Safety rules enforced by the engine:

* One statement, `SELECT` only. Unknown or system functions and tables outside the scanned schema are rejected.
* A role that sees a masked value may not filter, join, group or sort on that column, so values cannot be guessed with `WHERE card_number LIKE '4111%'`.
* Both adapters open read-only connections (SQLite `mode=ro`, PostgreSQL read-only transaction and a SELECT-only database user).
* A column tagged with an entity that a role has no rule for is redacted by default.
* Tags, manual overrides and the audit log live in a separate metadata file, never in the protected database.

## Run it

```bash
pip install -r requirements.txt
python -m smartmask.seed                       # synthetic bank data -> data/bank.db
export SMARTMASK_PG_ADMIN_DSN="host=localhost port=5433 dbname=postgres user=postgres"   # optional, loads PostgreSQL too
python -m smartmask.seed
streamlit run app.py                           # demo UI
python -m smartmask.cli --role support --show-sql "SELECT card_number FROM cards LIMIT 3"
uvicorn smartmask.api:app --port 8000          # API docs at /docs
python -m pytest -q tests                      # 60 tests
python -m smartmask.benchmark                  # scanner accuracy on a labelled schema
```

PostgreSQL connection for the app comes from `SMARTMASK_PG_DSN` (default: `host=localhost port=5433 dbname=postgres user=smartmask_app`).

## Measured results

Scanner benchmark: a self-built labelled schema of 63 synthetic columns (30 sensitive, 33 decoys).

| Measure | Result |
|---|---|
| Precision | 96% (24 of 25 tagged columns were correct) |
| Recall | 80% (24 of 30 sensitive columns found) |
| Entity accuracy on hits | 100% |
| Clearly named sensitive columns | 16 of 16 found |
| Cryptically named columns with distinctive values | 8 of 8 found |
| Cryptic name and no distinctive value pattern | 0 of 6 found (by design, fixable with a manual override) |
| False positive | `balance_sheet_year` (integer column whose name contains "balance") |

The benchmark was written by the same author as the scanner, so treat it as a regression check and not as an independent accuracy claim. Free-text columns that contain PII inside sentences are out of scope.

## Known limitations

* Strict by design: analysts cannot filter on a protected column even for legitimate analytics.
* Hash tokens use a deployment-wide salt, so identical values give identical tokens (joins work). Change `SMARTMASK_SALT` and keep it secret.
* Not a certified GDPR or HIPAA control. All demo data is synthetic.

## AI assistance disclosure

This project was built with the help of an AI coding assistant (Claude). The idea selection, review and submission are the author's.
