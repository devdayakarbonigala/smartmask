import hashlib
import os
import sqlite3

import pytest

from smartmask import benchmark, config
from smartmask.adapters import PostgresAdapter, SqliteAdapter
from smartmask.engine import MaskingEngine, PolicyViolation
from smartmask.policy import Policy
from smartmask.store import MetaStore


def _pg_available():
    try:
        PostgresAdapter(config.PG_DSN)
        return True
    except Exception:
        return False


BACKENDS = ["sqlite"] + (["postgres"] if _pg_available() else [])


@pytest.fixture(params=BACKENDS)
def eng(request, tmp_path):
    ad = SqliteAdapter(config.SQLITE_PATH) if request.param == "sqlite" else PostgresAdapter(config.PG_DSN)
    e = MaskingEngine(ad, MetaStore(str(tmp_path / "meta.db")), Policy(), "test-salt")
    e.run_scan()
    return e


Q = "SELECT card_id, card_number FROM cards ORDER BY card_id LIMIT 3"


def test_admin_sees_raw(eng):
    rows = eng.execute("admin", Q).rows
    assert all(len(r[1]) == 19 and r[1].count("-") == 3 for r in rows)


def test_support_partial_card(eng):
    for _, card in eng.execute("support", Q).rows:
        assert card[4:5] == "-" and card[5:14] == "XXXX-XXXX" and len(card) == 19


def test_analyst_hash_is_salted_sha256_and_deterministic(eng):
    raw = eng.execute("admin", Q).rows
    hashed = eng.execute("analyst", Q).rows
    for (_, r), (_, h) in zip(raw, hashed):
        assert h == hashlib.sha256(("test-salt" + r).encode()).hexdigest()[:16]


def test_balance_redacted_for_non_admin(eng):
    q = "SELECT balance FROM accounts ORDER BY account_id LIMIT 3"
    assert all(v[0] is not None for v in eng.execute("admin", q).rows)
    for role in ("support", "analyst"):
        assert all(v[0] is None for v in eng.execute(role, q).rows)


def test_select_star_and_join_alias(eng):
    r = eng.execute("support", "SELECT * FROM customers c JOIN cards k ON k.customer_id=c.customer_id LIMIT 2")
    ssn = r.columns.index("ssn")
    assert r.rows[0][ssn].startswith("XXX-XX-")


def test_subquery_cannot_unmask(eng):
    r = eng.execute("analyst", "SELECT x FROM (SELECT card_number AS x FROM cards) t LIMIT 1")
    assert len(r.rows[0][0]) == 16 and "-" not in r.rows[0][0]


def test_cte_and_union(eng):
    r = eng.execute("support", "WITH t AS (SELECT email AS e FROM customers) SELECT e FROM t LIMIT 1")
    assert "***" in r.rows[0][0]
    r = eng.execute("support", "SELECT email FROM customers UNION SELECT email FROM customers LIMIT 1")
    assert "***" in r.rows[0][0]


@pytest.mark.parametrize("sql", [
    "SELECT * FROM cards WHERE card_number LIKE '4111%'",
    "SELECT card_id FROM cards ORDER BY card_number",
    "SELECT customer_id FROM customers WHERE ssn = '123-45-6789'",
    "SELECT a.account_id FROM accounts a WHERE a.balance > 1000",
    "SELECT customer_id FROM customers GROUP BY customer_id HAVING MAX(ssn) > '5'",
    "SELECT (SELECT 1 FROM cards k WHERE k.card_number = c.ssn) FROM customers c",
    "SELECT 1 FROM cards JOIN customers ON cards.card_number = customers.ssn",
])
def test_probing_predicates_denied_for_masked_roles(eng, sql):
    with pytest.raises(PolicyViolation):
        eng.execute("analyst", sql)
    with pytest.raises(PolicyViolation):
        eng.execute("support", sql)


def test_admin_may_filter(eng):
    assert eng.execute("admin", "SELECT card_id FROM cards WHERE card_number LIKE '4%' LIMIT 1")


@pytest.mark.parametrize("sql", [
    "DELETE FROM cards", "UPDATE cards SET card_number='x'", "DROP TABLE cards", "INSERT INTO cards VALUES (1)",
    "SELECT 1; SELECT 2", "SELECT pg_sleep(1)", "SELECT * FROM pg_user", "SELECT * FROM sqlite_master",
    "SELECT load_extension('x')", "SELECT * FROM information_schema.tables",
])
def test_dangerous_statements_denied_for_every_role(eng, sql):
    for role in ("admin", "support", "analyst"):
        with pytest.raises(PolicyViolation):
            eng.execute(role, sql)


def test_unknown_role(eng):
    with pytest.raises(KeyError):
        eng.execute("intern", Q)


def test_audit_log_records_ok_and_denied(eng):
    eng.execute("support", Q, user="alice")
    with pytest.raises(PolicyViolation):
        eng.execute("analyst", "SELECT * FROM cards WHERE card_number='x'", user="bob")
    rows = eng.store.audit_rows(5)
    statuses = {(r[1], r[3]) for r in rows}
    assert ("alice", "OK") in statuses and ("bob", "DENIED") in statuses


def test_underlying_data_untouched_and_db_is_readonly(eng):
    def checksum():
        _, rows, _ = eng.adapter.execute("SELECT card_id, card_number FROM cards ORDER BY card_id", 10_000)
        return hashlib.sha256(repr(rows).encode()).hexdigest()
    before = checksum()
    for role in ("admin", "support", "analyst"):
        eng.execute(role, "SELECT * FROM cards")
    assert checksum() == before
    with pytest.raises(Exception):
        eng.adapter.raw_execute_for_test("UPDATE cards SET card_number='0000' WHERE card_id=1")


def test_new_role_rule_defaults_to_redact():
    p = Policy()
    assert p.mask_for("support", "SOMETHING_NEW") == "redact"


@pytest.mark.skipif(len(BACKENDS) < 2, reason="needs both backends")
def test_backend_parity(tmp_path):
    out = {}
    for b in BACKENDS:
        ad = SqliteAdapter(config.SQLITE_PATH) if b == "sqlite" else PostgresAdapter(config.PG_DSN)
        e = MaskingEngine(ad, MetaStore(str(tmp_path / f"{b}.db")), Policy(), "test-salt")
        e.run_scan()
        q = "SELECT customer_id, full_name, email, phone, ssn, aadhaar_no, pan_no, date_of_birth FROM customers ORDER BY customer_id LIMIT 25"
        for role in ("support", "analyst"):
            out[(b, role)] = e.execute(role, q).rows
    for role in ("support", "analyst"):
        assert out[("sqlite", role)] == out[("postgres", role)]


def test_scanner_benchmark_floor():
    r = benchmark.run()
    assert r["precision"] >= 0.9 and r["recall"] >= 0.75 and r["entity_accuracy"] == 1.0
    assert r["by_group"]["named"] == "16/16" and r["by_group"]["cryptic"] == "8/8"


def test_override_can_fix_a_miss(tmp_path):
    ad = SqliteAdapter(config.SQLITE_PATH)
    e = MaskingEngine(ad, MetaStore(str(tmp_path / "m.db")), Policy(), "s")
    e.run_scan()
    e.store.set_override(e.db_key, "transactions", "reference_no", "ACCOUNT_NO")
    e.store.set_override(e.db_key, "cards", "credit_limit", "NONE")
    r = e.execute("support", "SELECT reference_no, credit_limit FROM transactions t JOIN cards c ON 1=1 LIMIT 1")
    assert r.rows[0][0].startswith("****") and r.rows[0][1] is not None
