"""AI assist: the local model, the optional LLM signal and the human-approval rule."""

import json
import sqlite3
import urllib.error

import pytest

from smartmask import ai_assist as ai
from smartmask.adapters import SqliteAdapter
from smartmask.engine import MaskingEngine
from smartmask.policy import Policy
from smartmask.scanner import scan
from smartmask.store import MetaStore

PANS = ["ABCDE1234F", "QWERT9876Z", "LMNOP4321K", "ZXCVB1111A", "PLMKO2222Q"]
CARDS = ["4111-1111-1111-1111", "5500-0000-0000-0004", "4012-8888-8888-1881", "5105-1051-0510-5100"]


@pytest.fixture(scope="module")
def model():
    return ai.get_model()


def test_shapes_hide_the_actual_values():
    assert ai.shape("ABCDE1234F") == "AAAAA9999A"
    assert ai.shape("asha.rao@mail.com") == "aaaa.aaa@aaaa.aaa"
    assert ai.shape("4111-1111") == "9999-9999"
    assert ai.shape("x" * 100) == "a" * 24  # long values are cut


def test_model_training_is_deterministic():
    a, b = ai.ColumnModel(seed=7), ai.ColumnModel(seed=7)
    sh = ai.top_shapes(PANS)
    assert a.predict("col_7", sh) == b.predict("col_7", sh)


def test_local_model_names_cryptic_columns_by_their_values(model):
    assert model.predict("col_7", ai.top_shapes(PANS)).entity == "PAN"
    assert model.predict("x3", ai.top_shapes(CARDS)).entity == "CARD"


def test_local_model_stays_quiet_on_ordinary_columns(model):
    assert model.predict("status", ai.top_shapes(["OPEN", "FROZEN", "OPEN", "ACTIVE"])).entity is None
    assert model.predict("city", ai.top_shapes(["Guntur", "Mumbai", "Pune"])).entity is None


def test_empty_sample_gives_no_opinion(model):
    assert model.predict("anything", []).entity is None


# ---- LLM signal: validation, privacy, failure handling ----------------------------------------
def _answer(text):
    return {"content": [{"type": "text", "text": text}]}


def test_llm_answer_is_validated():
    ok = ai.parse_llm_answer('{"entity": "PAN", "confidence": 0.9, "reason": "tax id shape"}')
    assert ok and ok.entity == "PAN"
    assert ai.parse_llm_answer('{"entity": "NONE", "confidence": 0.2, "reason": ""}').entity is None
    for bad in [
        "not json",
        '{"entity": "PASSPORT", "confidence": 0.9}',
        '{"entity": "PAN", "confidence": 7}',
        '{"confidence": 0.5}',
        "[]",
    ]:
        assert ai.parse_llm_answer(bad) is None


def test_llm_request_carries_shapes_never_raw_values():
    seen = {}

    def transport(payload):
        seen.update(payload)
        return _answer('{"entity": "PAN", "confidence": 0.8, "reason": "shape"}')

    sig = ai.llm_suggest("kyc", "col_7", "TEXT", ai.top_shapes(PANS), transport)
    sent = json.dumps(seen)
    assert sig.entity == "PAN"
    assert "AAAAA9999A" in sent and not any(p in sent for p in PANS)
    assert seen["temperature"] == 0 and seen["model"]


def test_llm_failure_returns_none_instead_of_guessing():
    def boom(payload):
        raise urllib.error.URLError("offline")

    assert ai.llm_suggest("t", "c", "TEXT", [("999", 1)], boom) is None
    assert ai.llm_suggest("t", "c", "TEXT", [("999", 1)], lambda p: {"content": []}) is None


def test_llm_is_off_without_a_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert ai.llm_enabled() is False
    assert ai.llm_suggest("t", "c", "TEXT", [("999", 1)]) is None


# ---- the vote and the approval rule ------------------------------------------------------------
@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "ai.db")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (id TEXT, col_7 TEXT, email_addr TEXT, status TEXT)")
    for i in range(40):
        con.execute("INSERT INTO t VALUES (?,?,?,?)", (f"C{i:06d}", PANS[i % 5], f"user{i}@mail{i % 4}.com", "OPEN"))
    con.commit()
    con.close()
    return path


def test_review_agrees_when_rules_and_model_match(db, model):
    ad = SqliteAdapter(db)
    tags = {(t.table, t.column): t for t in scan(ad)}
    rows = {r.column: r for r in ai.review_all(ad, tags, model)}
    assert rows["email_addr"].verdict == "agree"
    assert rows["status"].verdict == "clear" and rows["id"].verdict == "clear"


def test_suggestion_needs_approval_and_changes_nothing_until_then(db, model, tmp_path):
    ad = SqliteAdapter(db)
    store = MetaStore(str(tmp_path / "m.db"))
    eng = MaskingEngine(ad, store, Policy(), "salt")
    eng.run_scan()
    before = store.load_tags(eng.db_key)
    reviews = ai.review_all(ad, {}, model)  # pretend the rules found nothing
    sug = next(r for r in reviews if r.column == "col_7")
    assert sug.verdict == "suggest" and sug.suggestion == "PAN" and sug.needs_review
    assert store.load_tags(eng.db_key).keys() == before.keys()  # reviewing alone changes no tag
    ai.approve(store, eng.db_key, sug)
    assert store.load_tags(eng.db_key)[("t", "col_7")].entity == "PAN"


def test_nothing_to_approve_for_clear_columns(db, model, tmp_path):
    ad = SqliteAdapter(db)
    r = next(x for x in ai.review_all(ad, {}, model) if x.column == "status")
    with pytest.raises(ValueError):
        ai.approve(MetaStore(str(tmp_path / "m.db")), "k", r)


def test_llm_signal_is_used_only_for_disagreements(db, model):
    calls = []

    def transport(payload):
        calls.append(1)
        return _answer('{"entity": "PAN", "confidence": 0.9, "reason": "shape"}')

    ad = SqliteAdapter(db)
    tags = {(t.table, t.column): t for t in scan(ad) if t.column != "col_7"}  # pretend the rules missed col_7
    rows = {r.column: r for r in ai.review_all(ad, tags, model, use_llm=True, transport=transport)}
    assert rows["email_addr"].llm is None  # rules and model agreed, so the LLM was not asked
    assert calls  # it was asked about the column the rules missed
    assert rows["col_7"].llm == "PAN" and "LLM agrees" in rows["col_7"].note


def test_branch_contact_details_are_not_suggested(model):
    rv = ai.review_column("branches", "branch_email", "TEXT", ["a@b.com", "c@d.org", "e@f.net"], None, model)
    assert rv.verdict == "clear"


# ---- automatic mode ----------------------------------------------------------------------------
def _rv(verdict, sug=None, ml=None, prob=0.0, llm=None, rules=None):
    return ai.Review("t", "c", rules, ml, prob, llm, verdict, sug, "n")


def test_auto_apply_adds_masks_only_when_confident(tmp_path):
    store = MetaStore(str(tmp_path / "m.db"))
    sure = _rv("suggest", "PAN", ml="PAN", prob=0.95)
    unsure = ai.Review("t", "d", None, "PAN", 0.7, None, "suggest", "PAN", "n")
    conflict = ai.Review("t", "e", "PHONE", "PAN", 0.99, None, "conflict", "PAN", "n")
    done = ai.auto_apply(store, "k", [sure, unsure, conflict])
    assert [r.column for r in done] == ["c"]
    assert any("auto-tag" in str(row) for row in store.audit_rows(10))


def test_auto_apply_never_removes_a_mask(tmp_path):
    store = MetaStore(str(tmp_path / "m.db"))
    removal = _rv("conflict", None, ml=None, prob=0.9, rules="EMAIL")
    assert ai.auto_apply(store, "k", [removal]) == []


def test_auto_applied_mask_changes_what_a_restricted_role_sees(db, model, tmp_path):
    ad = SqliteAdapter(db)
    store = MetaStore(str(tmp_path / "m.db"))
    eng = MaskingEngine(ad, store, Policy(), "salt")
    eng.run_scan()
    reviews = ai.review_all(ad, {}, model)
    sure = [r for r in reviews if r.column == "col_7"]
    sure[0].ml_prob = 1.0
    assert ai.auto_apply(store, eng.db_key, sure)
    raw = eng.execute("admin", "SELECT col_7 FROM t LIMIT 1").rows[0][0]
    masked = eng.execute("analyst", "SELECT col_7 FROM t LIMIT 1").rows[0][0]
    assert raw in PANS and masked != raw


def test_decision_reports_mask_or_do_not_mask():
    assert ai.decision(_rv("suggest", "PAN", ml="PAN", prob=0.9)) == ("MASK", "PAN")
    assert ai.decision(_rv("clear")) == ("DO NOT MASK", "")
