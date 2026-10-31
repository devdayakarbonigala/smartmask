"""Login, role binding and the exposure ledger."""

import json
from collections import Counter

import pytest

from smartmask import auth, ui
from smartmask.policy import Policy
from smartmask.scanner import ColumnTag


@pytest.fixture()
def users(tmp_path):
    path = tmp_path / "u.json"
    path.write_text(json.dumps({"users": {"sam": {"role": "support", "password": auth.hash_password("S3cret!")}}}))
    return auth.load_users(path)


def test_correct_password_returns_the_bound_role(users):
    assert auth.authenticate(users, "sam", "S3cret!") == "support"
    assert auth.authenticate(users, "  SAM ", "S3cret!") == "support"


def test_wrong_password_unknown_user_and_empty_input_are_rejected(users):
    assert auth.authenticate(users, "sam", "wrong") is None
    assert auth.authenticate(users, "ghost", "S3cret!") is None
    assert auth.authenticate(users, "", "") is None


def test_hashes_are_salted_and_never_contain_the_password():
    a, b = auth.hash_password("same"), auth.hash_password("same")
    assert a != b and "same" not in a
    assert auth.verify_password("same", a) and not auth.verify_password("other", a)
    assert not auth.verify_password("same", "not-a-hash")


def test_a_user_with_an_unknown_role_is_refused(tmp_path):
    path = tmp_path / "u.json"
    path.write_text(json.dumps({"users": {"x": {"role": "root", "password": auth.hash_password("p")}}}))
    with pytest.raises(ValueError):
        auth.load_users(path)


def test_shipped_demo_accounts_load_and_log_in():
    users = auth.load_users()
    assert {u["role"] for u in users.values()} == {"admin", "support", "analyst"}
    assert auth.authenticate(users, "analyst", "Analyst@demo1") == "analyst"


def test_exposure_counts_what_each_role_receives():
    tags = {
        ("t", "ssn"): ColumnTag("t", "ssn", "TEXT", "SSN", "PII_HIGH", 1.0, True, 1.0),
        ("t", "bal"): ColumnTag("t", "bal", "REAL", "BALANCE", "FINANCIAL_CONFIDENTIAL", 1.0, True, 1.0),
    }
    out = ui.exposure(tags, Policy())
    assert out["admin"] == Counter({"none": 2})
    assert out["support"] == Counter({"partial": 1, "redact": 1})
    assert out["analyst"] == Counter({"hash": 1, "redact": 1})
    assert "100.00%" in ui.ledger_html({"admin": out["admin"]})
