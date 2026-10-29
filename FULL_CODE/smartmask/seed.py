"""Synthetic bank data (no real people). Loads the SAME rows into SQLite and PostgreSQL."""

from __future__ import annotations

import os
import random
import sqlite3
import string

from faker import Faker

from .checks import verhoeff_generate

SCHEMA = {
    "customers": [
        ("customer_id", "INTEGER"),
        ("full_name", "TEXT"),
        ("email", "TEXT"),
        ("phone", "TEXT"),
        ("date_of_birth", "TEXT"),
        ("ssn", "TEXT"),
        ("aadhaar_no", "TEXT"),
        ("pan_no", "TEXT"),
        ("city", "TEXT"),
        ("kyc_status", "TEXT"),
        ("support_note", "TEXT"),
    ],
    "accounts": [
        ("account_id", "INTEGER"),
        ("customer_id", "INTEGER"),
        ("account_number", "TEXT"),
        ("account_type", "TEXT"),
        ("balance", "NUMERIC(14,2)"),
        ("opened_on", "TEXT"),
    ],
    "cards": [
        ("card_id", "INTEGER"),
        ("customer_id", "INTEGER"),
        ("card_number", "TEXT"),
        ("card_type", "TEXT"),
        ("expiry", "TEXT"),
        ("credit_limit", "NUMERIC(12,2)"),
    ],
    "transactions": [
        ("txn_id", "INTEGER"),
        ("account_id", "INTEGER"),
        ("reference_no", "TEXT"),
        ("amount", "NUMERIC(12,2)"),
        ("merchant", "TEXT"),
        ("txn_date", "TEXT"),
    ],
}


def _aadhaar(rng):
    base = str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(10))
    return base + verhoeff_generate(base)


def _pan(rng):
    return (
        "".join(rng.choice(string.ascii_uppercase) for _ in range(5))
        + "".join(rng.choice(string.digits) for _ in range(4))
        + rng.choice(string.ascii_uppercase)
    )


def generate(n_customers: int = 120, seed: int = 7) -> dict[str, list[tuple]]:
    fake = Faker("en_IN")
    fake_us = Faker("en_US")
    Faker.seed(seed)
    rng = random.Random(seed)
    data: dict[str, list[tuple]] = {k: [] for k in SCHEMA}
    acct_id = card_id = txn_id = 0
    for cid in range(1, n_customers + 1):
        name = fake.name()
        email = f"{name.lower().replace(' ', '.').replace('..', '.')}{rng.randint(1, 99)}@{rng.choice(['gmail.com', 'outlook.com', 'yahoo.in', 'example.org'])}"
        phone = f"+91 {rng.randint(6, 9)}{rng.randint(10**8, 10**9 - 1)}"
        pan = _pan(rng)
        note = rng.choice(
            [
                f"Customer called from {phone} about a failed UPI payment. PAN {pan} confirmed.",
                f"Asked to update e-mail to {email}. Verified by branch.",
                "Statement requested for the last quarter. No identifiers shared.",
                f"Re-KYC reminder sent. Customer shared PAN {pan} over chat; advised not to.",
            ]
        )
        data["customers"].append(
            (
                cid,
                name,
                email,
                phone,
                fake.date_of_birth(minimum_age=19, maximum_age=80).isoformat(),
                fake_us.ssn(),
                _aadhaar(rng),
                pan,
                fake.city(),
                rng.choice(["VERIFIED", "VERIFIED", "PENDING", "RE-KYC"]),
                note,
            )
        )
        for _ in range(rng.randint(1, 2)):
            acct_id += 1
            data["accounts"].append(
                (
                    acct_id,
                    cid,
                    "".join(rng.choice(string.digits) for _ in range(12)),
                    rng.choice(["SAVINGS", "CURRENT", "SALARY"]),
                    round(rng.uniform(500, 2_500_000), 2),
                    fake.date_between("-10y", "-30d").isoformat(),
                )
            )
            for _ in range(rng.randint(2, 4)):
                txn_id += 1
                data["transactions"].append(
                    (
                        txn_id,
                        acct_id,
                        "".join(rng.choice(string.digits) for _ in range(16)),
                        round(rng.uniform(40, 90_000), 2),
                        fake.company(),
                        fake.date_between("-90d", "today").isoformat(),
                    )
                )
        for _ in range(rng.randint(0, 2)):
            card_id += 1
            num = fake.credit_card_number("visa16" if rng.random() < 0.6 else "mastercard")
            num = "-".join(num[i : i + 4] for i in range(0, 16, 4))
            data["cards"].append(
                (
                    card_id,
                    cid,
                    num,
                    rng.choice(["VISA", "MASTERCARD"]),
                    fake.credit_card_expire(),
                    float(rng.choice([50000, 100000, 250000, 500000])),
                )
            )
    return data


def _sqlite_type(t):
    return "REAL" if t.startswith("NUMERIC") else t


def load_sqlite(path: str, data: dict[str, list[tuple]]):
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    for t, cols in SCHEMA.items():
        con.execute(f"CREATE TABLE {t} (" + ", ".join(f"{c} {_sqlite_type(ty)}" for c, ty in cols) + ")")
        con.executemany(f"INSERT INTO {t} VALUES ({','.join('?' * len(cols))})", data[t])
    con.commit()
    con.close()


def load_postgres(admin_dsn: str, app_user: str, data: dict[str, list[tuple]]):
    """Creates tables as the admin DSN and grants SELECT-only to a least-privilege app user."""
    import psycopg

    with psycopg.connect(admin_dsn, autocommit=True) as con:
        cur = con.cursor()
        for t in reversed(list(SCHEMA)):
            cur.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
        for t, cols in SCHEMA.items():
            pg_cols = []
            for c, ty in cols:
                if c in ("date_of_birth", "opened_on", "txn_date"):
                    ty = "DATE"
                pg_cols.append(f"{c} {ty}")
            cur.execute(f"CREATE TABLE {t} (" + ", ".join(pg_cols) + ")")
            cur.executemany(f"INSERT INTO {t} VALUES ({','.join(['%s'] * len(cols))})", data[t])
        cur.execute(
            f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{app_user}') "
            f"THEN CREATE ROLE {app_user} LOGIN; END IF; END $$"
        )
        cur.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {app_user}")
        cur.execute(f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA public FROM {app_user}")


def main():
    data = generate()
    os.makedirs("data", exist_ok=True)
    load_sqlite("data/bank.db", data)
    print({t: len(r) for t, r in data.items()}, "-> data/bank.db")
    dsn = os.environ.get("SMARTMASK_PG_ADMIN_DSN")
    if dsn:
        load_postgres(dsn, os.environ.get("SMARTMASK_PG_APP_USER", "smartmask_app"), data)
        print("PostgreSQL loaded; app role has SELECT only")


if __name__ == "__main__":
    main()
