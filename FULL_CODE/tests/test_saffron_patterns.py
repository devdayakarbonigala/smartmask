"""Messy-data cases taken from the organisers' bank pack, rebuilt here as tiny synthetic fixtures.

The pack itself is not in this repository. These tests cover its traps: UPPER-CASE column names,
SSNs that start with 9, Aadhaar numbers that fail the Verhoeff check, abbreviated column names,
identifiers hidden inside sentences and JSON, and card numbers hiding in a reference column.
"""

import sqlite3

import pytest

from smartmask import scanner
from smartmask.adapters import SqliteAdapter
from smartmask.engine import MaskingEngine, PolicyViolation
from smartmask.policy import Policy
from smartmask.scrub import scrub_text
from smartmask.store import MetaStore

CARDS = ["4111111111111111", "5555555555554444", "4012888888881881", "5105105105105100"]


@pytest.fixture()
def messy_db(tmp_path):
    path = str(tmp_path / "messy.db")
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE customers (customer_id TEXT, cust_nm TEXT, mob_no TEXT, addr_line1 TEXT, city TEXT);
    CREATE TABLE intl (customer_id TEXT, ssn TEXT);
    CREATE TABLE kyc (customer_id TEXT, aadhaar_no TEXT, kyc_meta TEXT);
    CREATE TABLE CARDS (CARD_REF TEXT, "CARD_NO" TEXT, NAME_ON_CARD TEXT);
    CREATE TABLE tickets (ticket_id TEXT, ticket_text TEXT);
    CREATE TABLE txns (txn_id TEXT, ref_no TEXT);
    """)
    names = ["Asha Rao", "Ravi Kumar", "Neha Gill", "Joseph Pinto", "Kavya Hegde", "Arnab Dutta"]
    for i in range(40):
        n = names[i % len(names)]
        con.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?)",
            (
                f"C{i}",
                n,
                ["9000090272", "+91-9999981099", "90000 69097", "+919000041727"][i % 4],
                f"Flat {i + 1}, Kesar Residency",
                "Guntur",
            ),
        )
        con.execute("INSERT INTO intl VALUES (?,?)", (f"C{i}", ["935-22-8793", "960 46 5982", "969266389"][i % 3]))
        con.execute(
            "INSERT INTO kyc VALUES (?,?,?)",
            (
                f"C{i}",
                f"{2511 + i} 2909 99{i % 10}6",
                '{"src": "IN-PERSON", "uid": "402850429751", "pan": "CGWPD0000V", "father_name": "Kuldeep Gill"}',
            ),
        )
        con.execute("INSERT INTO CARDS VALUES (?,?,?)", (f"R{i}", CARDS[i % 4], n.upper()))
        con.execute(
            "INSERT INTO tickets VALUES (?,?)",
            (
                f"T{i}",
                [
                    "Card chori ho gaya, PAN no FSRPS0000G. Mob +91-9999964902 pe call karo.",
                    "Cust shared full card no 5105105184750255 in chat. Mail me at ankit.saxena@inbox.example please.",
                    "KYC UPDATE KARNA HAI, AADHAAR NO 638430776322 HAI.",
                    "Statement not received for the last quarter, please check.",
                ][i % 4],
            ),
        )
        # ref_no: mostly ordinary references, sometimes a real card number (spaced, hyphenated or plain)
        ref = [f"UTRAB{i:011d}", CARDS[i % 4], " ".join(CARDS[i % 4][k : k + 4] for k in range(0, 16, 4)), f"{i:06d}"][i % 4]
        con.execute("INSERT INTO txns VALUES (?,?)", (f"{i:016d}", ref))
    con.commit()
    con.close()
    return path


@pytest.fixture()
def eng(messy_db, tmp_path):
    e = MaskingEngine(SqliteAdapter(messy_db), MetaStore(str(tmp_path / "meta.db")), Policy(), "test-salt")
    e.run_scan()
    return e


def entity(eng, table, column):
    tag = eng.store.load_tags(eng.db_key).get((table, column))
    return tag.entity if tag else None


@pytest.mark.parametrize(
    "table,column,expected",
    [
        ("intl", "ssn", "SSN"),
        ("kyc", "aadhaar_no", "AADHAAR"),
        ("customers", "mob_no", "PHONE"),
        ("customers", "cust_nm", "NAME"),
        ("customers", "addr_line1", "ADDRESS"),
        ("cards", "card_no", "CARD"),
        ("cards", "name_on_card", "NAME"),
        ("kyc", "kyc_meta", "FREETEXT"),
        ("tickets", "ticket_text", "FREETEXT"),
        ("txns", "ref_no", "FREETEXT"),
    ],
)
def test_scanner_finds_messy_columns(eng, table, column, expected):
    assert entity(eng, table, column) == expected


@pytest.mark.parametrize(
    "table,column", [("customers", "city"), ("customers", "customer_id"), ("txns", "txn_id"), ("cards", "card_ref")]
)
def test_scanner_leaves_ordinary_columns_alone(eng, table, column):
    assert entity(eng, table, column) is None


def test_support_masks_ssn_aadhaar_phone_name_and_address(eng):
    r = eng.execute("support", "SELECT ssn FROM intl LIMIT 3")
    assert all(v[0].startswith("XXX-XX-") for v in r.rows)
    r = eng.execute("support", "SELECT aadhaar_no FROM kyc LIMIT 1")
    assert r.rows[0][0].startswith("XXXX XXXX ")
    r = eng.execute("support", "SELECT mob_no, cust_nm, addr_line1 FROM customers LIMIT 4")
    for mob, name, addr in r.rows:
        assert mob.startswith("******") and name.endswith("***") and addr.endswith("***")


def test_analyst_gets_hashes_and_redacted_addresses(eng):
    r = eng.execute("analyst", "SELECT ssn FROM intl LIMIT 2")
    assert all(len(v[0]) == 16 and "-" not in v[0] for v in r.rows)
    r = eng.execute("analyst", "SELECT addr_line1 FROM customers LIMIT 2")
    assert all(v[0] == "[REDACTED]" for v in r.rows)


def test_admin_sees_everything_raw(eng):
    assert eng.execute("admin", "SELECT ssn FROM intl LIMIT 1").rows[0][0] == "935-22-8793"
    assert "FSRPS0000G" in eng.execute("admin", "SELECT ticket_text FROM tickets LIMIT 1").rows[0][0]


@pytest.mark.parametrize("role", ["support", "analyst"])
def test_free_text_identifiers_are_removed(eng, role):
    rows = eng.execute(role, "SELECT ticket_text FROM tickets").rows
    text = " ".join(r[0] for r in rows)
    for secret in ("FSRPS0000G", "9999964902", "5105105184750255", "ankit.saxena", "638430776322"):
        assert secret not in text
    assert "[PAN]" in text and "[PHONE]" in text and "[CARD]" in text and "[EMAIL]" in text and "[AADHAAR]" in text
    assert "Statement not received" in text  # ordinary words are left alone


@pytest.mark.parametrize("role", ["support", "analyst"])
def test_json_text_is_scrubbed_and_stays_valid_text(eng, role):
    meta = eng.execute(role, "SELECT kyc_meta FROM kyc LIMIT 1").rows[0][0]
    for secret in ("402850429751", "CGWPD0000V", "Kuldeep"):
        assert secret not in meta
    assert '"src": "IN-PERSON"' in meta


@pytest.mark.parametrize("role", ["support", "analyst"])
def test_card_numbers_hidden_in_a_reference_column_are_removed(eng, role):
    refs = [r[0] for r in eng.execute(role, "SELECT ref_no FROM txns").rows]
    assert not any(c in ref.replace(" ", "") for ref in refs for c in CARDS)
    assert any(ref.startswith("UTRAB") for ref in refs)  # ordinary references survive


def test_upper_case_table_and_quoted_column_are_accepted(eng):
    for sql in (
        "SELECT card_no FROM cards LIMIT 2",
        'SELECT "CARD_NO" FROM "CARDS" LIMIT 2',
        "SELECT CARD_NO FROM CARDS LIMIT 2",
    ):
        assert all(len(v[0]) == 16 for v in eng.execute("analyst", sql).rows)


def test_probing_a_newly_tagged_column_is_denied(eng):
    with pytest.raises(PolicyViolation):
        eng.execute("analyst", "SELECT customer_id FROM kyc WHERE aadhaar_no LIKE '2511%'")


def test_scan_failure_fails_closed(messy_db, tmp_path):
    class Broken(SqliteAdapter):
        def sample(self, table, column, n):
            raise RuntimeError("column does not exist")

    e = MaskingEngine(Broken(messy_db), MetaStore(str(tmp_path / "m.db")), Policy(), "s")
    for role in ("admin", "support", "analyst"):
        with pytest.raises(PolicyViolation, match="refusing to serve"):
            e.execute(role, "SELECT ssn FROM intl")


def test_queries_scan_automatically_when_no_tags_exist(messy_db, tmp_path):
    e = MaskingEngine(SqliteAdapter(messy_db), MetaStore(str(tmp_path / "m.db")), Policy(), "s")
    assert e.execute("support", "SELECT ssn FROM intl LIMIT 1").rows[0][0].startswith("XXX-XX-")


def test_tags_belong_to_one_schema(messy_db, tmp_path):
    store = MetaStore(str(tmp_path / "shared.db"))
    first = MaskingEngine(SqliteAdapter(messy_db), store, Policy(), "s")
    first.run_scan()
    other = str(tmp_path / "other.db")
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE intl (customer_id TEXT, ssn TEXT)")
    con.execute("INSERT INTO intl VALUES ('C1', '935-22-8793')")
    con.commit()
    con.close()
    second = MaskingEngine(SqliteAdapter(other), store, Policy(), "s")
    assert first.db_key != second.db_key
    assert second.execute("support", "SELECT ssn FROM intl").rows[0][0].startswith("XXX-XX-")


@pytest.mark.parametrize(
    "raw,clean",
    [
        ("call 9000090272 now", "call [PHONE] now"),
        ("mob +91-90000-29246.", "mob [PHONE]."),
        ("RRN 527507844335 TAT 5", "RRN 527507844335 TAT 5"),
        ("UPI/527402653616/bhavnadave@pragatiupi/maid", "UPI/527402653616/[UPI-ID]/maid"),
        ("SSN 935-22-8793 W-9", "SSN [SSN] W-9"),
        ("Aadhaar 6384 3077 6322 ok", "Aadhaar [AADHAAR] ok"),
    ],
)
def test_scrub_rules(raw, clean):
    assert scrub_text(raw) == clean


def test_scrub_handles_none():
    assert scrub_text(None) is None


def test_mixed_card_content_needs_mostly_valid_card_numbers():
    random_refs = [f"{i:016d}" for i in range(1000000000000000, 1000000000000040)]  # most fail Luhn
    assert not scanner._mixed_card_content(random_refs)
    assert scanner._mixed_card_content(CARDS * 2 + ["UTRAB0000000001"])


# ---- HIPAA geography identifier: US ZIP codes --------------------------------------------------
def test_us_zip_is_masked_but_indian_pincode_is_not(tmp_path):
    path = str(tmp_path / "zip.db")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE intl (cust_id TEXT, us_zip TEXT, pincode TEXT)")
    for i in range(30):
        con.execute("INSERT INTO intl VALUES (?,?,?)", (f"C{i}", f"{94000 + i}", f"{522000 + i}"))
    con.commit()
    con.close()
    eng = MaskingEngine(SqliteAdapter(path), MetaStore(str(tmp_path / "m.db")), Policy(), "s")
    eng.run_scan()
    tags = {t.column: t.entity for t in eng.store.load_tags(eng.db_key).values()}
    assert tags.get("us_zip") == "ZIP" and "pincode" not in tags
    assert eng.execute("admin", "SELECT us_zip FROM intl ORDER BY cust_id LIMIT 1").rows[0][0] == "94000"
    assert eng.execute("support", "SELECT us_zip FROM intl ORDER BY cust_id LIMIT 1").rows[0][0] == "940**"
    assert eng.execute("analyst", "SELECT us_zip FROM intl ORDER BY cust_id LIMIT 1").rows[0][0] == "[REDACTED]"
