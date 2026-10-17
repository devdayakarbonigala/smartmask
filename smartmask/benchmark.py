"""Labelled scanner benchmark. Builds a throw-away SQLite schema with known answers (including hard,
misleadingly named and decoy columns), runs the scanner, and reports precision / recall honestly."""
from __future__ import annotations

import os
import random
import sqlite3
import string
import tempfile

from .adapters import SqliteAdapter
from .checks import luhn_ok, verhoeff_generate
from .scanner import scan

N = 60


def _digits(rng, k): return "".join(rng.choice(string.digits) for _ in range(k))


def _luhn_card(rng):
    while True:
        d = "4" + _digits(rng, 14)
        for c in string.digits:
            if luhn_ok(d + c):
                return "-".join((d + c)[i:i + 4] for i in range(0, 16, 4))


def _nonluhn16(rng):
    while True:
        d = _digits(rng, 16)
        if not luhn_ok(d):
            return d


def _ssn(rng): return f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
def _aad(rng):
    b = str(rng.randint(2, 9)) + _digits(rng, 10)
    return b + verhoeff_generate(b)
def _pan(rng): return "".join(rng.choice(string.ascii_uppercase) for _ in range(5)) + _digits(rng, 4) + rng.choice(string.ascii_uppercase)
def _email(rng): return f"user{rng.randint(1, 9999)}@{rng.choice(['mail.com', 'corp.in', 'example.org'])}"
def _phone(rng): return f"+91 {rng.randint(6, 9)}{_digits(rng, 9)}"
def _dob(rng): return f"{rng.randint(1950, 2004)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
def _name(rng): return rng.choice(["Asha", "Ravi", "Meera", "John", "Sana", "Kiran"]) + " " + rng.choice(["Rao", "Khan", "Smith", "Iyer", "Das"])
def _date(rng): return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"

# (column, sql type, generator, expected entity or None for non-sensitive, group)
COLUMNS = [
    # ---- sensitive, clearly named
    ("cust_ssn", "TEXT", _ssn, "SSN", "named"), ("customer_email", "TEXT", _email, "EMAIL", "named"),
    ("mobile_no", "TEXT", _phone, "PHONE", "named"), ("credit_card_number", "TEXT", _luhn_card, "CARD", "named"),
    ("aadhaar_number", "TEXT", _aad, "AADHAAR", "named"), ("pan_card", "TEXT", _pan, "PAN", "named"),
    ("dob", "TEXT", _dob, "DOB", "named"), ("account_balance", "REAL", lambda r: round(r.uniform(100, 9e6), 2), "BALANCE", "named"),
    ("savings_acct_no", "TEXT", lambda r: _digits(r, 12), "ACCOUNT_NO", "named"), ("first_name", "TEXT", _name, "NAME", "named"),
    ("holder_name", "TEXT", _name, "NAME", "named"), ("salary", "REAL", lambda r: round(r.uniform(2e5, 4e6), 2), "BALANCE", "named"),
    ("debit_card_no", "TEXT", _luhn_card, "CARD", "named"), ("email", "TEXT", _email, "EMAIL", "named"),
    ("phone", "TEXT", lambda r: _digits(r, 10), "PHONE", "named"), ("social_security_number", "TEXT", _ssn, "SSN", "named"),
    # ---- sensitive, cryptic name but distinctive values
    ("cc_no", "TEXT", _luhn_card, "CARD", "cryptic"), ("em", "TEXT", _email, "EMAIL", "cryptic"),
    ("contact", "TEXT", _phone, "PHONE", "cryptic"), ("govt_id", "TEXT", _aad, "AADHAAR", "cryptic"),
    ("tax_ref", "TEXT", _pan, "PAN", "cryptic"), ("identifier", "TEXT", _ssn, "SSN", "cryptic"),
    ("col_7", "TEXT", _luhn_card, "CARD", "cryptic"), ("data1", "TEXT", _email, "EMAIL", "cryptic"),
    # ---- sensitive, cryptic name AND no distinctive value pattern (expected misses)
    ("col_d", "TEXT", _dob, "DOB", "hard"), ("person", "TEXT", _name, "NAME", "hard"),
    ("amt_total", "REAL", lambda r: round(r.uniform(100, 9e6), 2), "BALANCE", "hard"),
    ("acct", "TEXT", lambda r: _digits(r, 12), "ACCOUNT_NO", "hard"), ("ref9", "TEXT", lambda r: _digits(r, 9), "SSN", "hard"),
    ("col_x", "TEXT", lambda r: _digits(r, 10), "PHONE", "hard"),
    # ---- non-sensitive decoys
    ("order_ref", "TEXT", _nonluhn16, None, "decoy"), ("invoice_no", "TEXT", lambda r: _digits(r, 10), None, "decoy"),
    ("txn_amount", "REAL", lambda r: round(r.uniform(10, 9e4), 2), None, "decoy"), ("quantity", "INTEGER", lambda r: r.randint(1, 20), None, "decoy"),
    ("pin_code", "TEXT", lambda r: _digits(r, 6), None, "decoy"), ("branch_code", "TEXT", lambda r: "BR" + _digits(r, 4), None, "decoy"),
    ("ifsc", "TEXT", lambda r: "HDFC0" + _digits(r, 6), None, "decoy"), ("product_name", "TEXT", lambda r: r.choice(["Savings Plus", "Gold Loan", "Home Loan"]), None, "decoy"),
    ("city", "TEXT", lambda r: r.choice(["Guntur", "Vizag", "Hyderabad"]), None, "decoy"), ("country", "TEXT", lambda r: "IN", None, "decoy"),
    ("status", "TEXT", lambda r: r.choice(["ACTIVE", "CLOSED"]), None, "decoy"), ("created_at", "TEXT", _date, None, "decoy"),
    ("updated_on", "TEXT", _date, None, "decoy"), ("card_type", "TEXT", lambda r: r.choice(["VISA", "MASTERCARD"]), None, "decoy"),
    ("card_network", "TEXT", lambda r: r.choice(["RUPAY", "VISA"]), None, "decoy"), ("email_verified", "INTEGER", lambda r: r.randint(0, 1), None, "decoy"),
    ("phone_type", "TEXT", lambda r: r.choice(["mobile", "landline"]), None, "decoy"), ("merchant_name", "TEXT", lambda r: r.choice(["Reliance Fresh", "Big Bazaar", "Amazon"]), None, "decoy"),
    ("bank_name", "TEXT", lambda r: r.choice(["SBI", "HDFC", "ICICI"]), None, "decoy"), ("ssn_verified", "TEXT", lambda r: r.choice(["Y", "N"]), None, "decoy"),
    ("pan_status", "TEXT", lambda r: r.choice(["ACTIVE", "INOPERATIVE"]), None, "decoy"), ("account_status", "TEXT", lambda r: r.choice(["OPEN", "FROZEN"]), None, "decoy"),
    ("account_type", "TEXT", lambda r: r.choice(["SAVINGS", "CURRENT"]), None, "decoy"), ("dob_verified", "TEXT", lambda r: r.choice(["Y", "N"]), None, "decoy"),
    ("balance_check_date", "TEXT", _date, None, "decoy"), ("employee_id", "INTEGER", lambda r: r.randint(1000, 9999), None, "decoy"),
    ("tracking_number", "TEXT", lambda r: _digits(r, 12), None, "decoy"), ("aadhaar_consent", "TEXT", lambda r: r.choice(["Y", "N"]), None, "decoy"),
    ("uuid", "TEXT", lambda r: "-".join(_digits(r, k) for k in (8, 4, 4, 4, 12)), None, "decoy"), ("description", "TEXT", lambda r: "monthly statement", None, "decoy"),
    ("latitude", "REAL", lambda r: round(r.uniform(8, 35), 5), None, "decoy"), ("house_number", "INTEGER", lambda r: r.randint(1, 400), None, "decoy"),
    ("balance_sheet_year", "INTEGER", lambda r: r.randint(2018, 2026), None, "decoy"),
]


def run(seed: int = 11) -> dict:
    rng = random.Random(seed)
    path = os.path.join(tempfile.mkdtemp(), "bench.db")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (" + ", ".join(f"{c} {ty}" for c, ty, *_ in COLUMNS) + ")")
    rows = [tuple(gen(rng) for _, _, gen, *_ in COLUMNS) for _ in range(N)]
    con.executemany(f"INSERT INTO t VALUES ({','.join('?' * len(COLUMNS))})", rows)
    con.commit(); con.close()

    found = {t.column: t for t in scan(SqliteAdapter(path))}
    tp = fp = fn = entity_ok = 0
    misses, false_pos, wrong_entity = [], [], []
    by_group: dict[str, list[int]] = {}
    for col, _, _, entity, group in COLUMNS:
        tag = found.get(col)
        g = by_group.setdefault(group, [0, 0])
        g[1] += 1
        if entity:
            if tag:
                tp += 1; g[0] += 1
                if tag.entity == entity: entity_ok += 1
                else: wrong_entity.append((col, entity, tag.entity))
            else:
                fn += 1; misses.append((col, entity, group))
        else:
            if tag:
                fp += 1; false_pos.append((col, tag.entity))
            else:
                g[0] += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "columns": len(COLUMNS), "sensitive": tp + fn, "non_sensitive": len(COLUMNS) - tp - fn,
        "tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "entity_accuracy": round(entity_ok / tp, 3) if tp else 0.0,
        "misses": misses, "false_positives": false_pos, "wrong_entity": wrong_entity,
        "by_group": {k: f"{a}/{b}" for k, (a, b) in by_group.items()},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
