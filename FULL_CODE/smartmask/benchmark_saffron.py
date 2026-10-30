"""Scanner check against the organisers' Saffron Bank pack (the pack itself is not part of this repository).

    python -m smartmask.benchmark_saffron path/to/saffron_bank.db

The sensitive-column labels below were written by the same team that tuned the scanner, after reading the
pack's column list and sample values. Treat the result as a regression check, not as independent accuracy.
Quasi-identifiers such as city, state, pincode and gender are deliberately not labelled sensitive here.
"""

from __future__ import annotations

import json
import sys

from .adapters import SqliteAdapter
from .scanner import scan

SENSITIVE: dict[tuple[str, str], str] = {
    ("customers", "cust_nm"): "NAME",
    ("customers", "pita_nm"): "NAME",
    ("customers", "dob_dt"): "DOB",
    ("customers", "mob_no"): "PHONE",
    ("customers", "alt_mob"): "PHONE",
    ("customers", "emailid"): "EMAIL",
    ("customers", "addr_line1"): "ADDRESS",
    ("customers", "addr_line2"): "ADDRESS",
    ("kyc_records", "pan_no"): "PAN",
    ("kyc_records", "aadhaar_no"): "AADHAAR",
    ("kyc_records", "kyc_meta"): "FREETEXT",
    ("international_customers", "ssn"): "SSN",
    ("international_customers", "us_addr"): "ADDRESS",
    ("international_customers", "us_phone"): "PHONE",
    ("international_customers", "us_zip"): "ZIP",
    ("accounts", "account_no"): "ACCOUNT_NO",
    ("accounts", "curr_bal"): "BALANCE",
    ("accounts", "od_limit_inr"): "BALANCE",
    ("accounts", "nominee_nm"): "NAME",
    ("accounts", "extra_info"): "FREETEXT",
    ("cards", "card_no"): "CARD",
    ("cards", "linked_acct"): "ACCOUNT_NO",
    ("cards", "name_on_card"): "NAME",
    ("cards", "credit_limit"): "BALANCE",
    ("cards", "outstanding_amt"): "BALANCE",
    ("transactions", "account_no"): "ACCOUNT_NO",
    ("transactions", "bal_after"): "BALANCE",
    ("transactions", "narration"): "FREETEXT",
    ("transactions", "counterparty"): "FREETEXT",
    ("transactions", "ref_no"): "FREETEXT",
    ("support_tickets", "ticket_text"): "FREETEXT",
    ("support_tickets", "notes"): "FREETEXT",
    ("loan_applications", "col_7"): "PAN",
    ("loan_applications", "declared_income_inr"): "BALANCE",
    ("loan_applications", "sanctioned_amt_inr"): "BALANCE",
    ("loan_applications", "remarks"): "FREETEXT",
}


def run(db_path: str) -> dict:
    schema = SqliteAdapter(db_path).schema()
    columns = sum(len(c) for c in schema.values())
    tagged = {(t.table.lower(), t.column.lower()): t.entity for t in scan(SqliteAdapter(db_path))}
    tp = [k for k in tagged if k in SENSITIVE]
    return {
        "columns": columns,
        "sensitive_labelled": len(SENSITIVE),
        "tagged": len(tagged),
        "precision": len(tp) / len(tagged) if tagged else 0.0,
        "recall": len(tp) / len(SENSITIVE),
        "entity_accuracy": sum(1 for k in tp if tagged[k] == SENSITIVE[k]) / len(tp) if tp else 0.0,
        "missed": sorted(k for k in SENSITIVE if k not in tagged),
        "false_positives": sorted(k for k in tagged if k not in SENSITIVE),
        "wrong_entity": sorted((k, tagged[k], SENSITIVE[k]) for k in tp if tagged[k] != SENSITIVE[k]),
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    print(json.dumps(run(sys.argv[1]), indent=2, default=str))
