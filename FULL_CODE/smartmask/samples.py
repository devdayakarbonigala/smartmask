"""Sample queries for the demo UI, chosen to match whichever database is connected."""

DEMO = {
    "Contact details": "SELECT customer_id, full_name, email, phone, date_of_birth FROM customers ORDER BY customer_id LIMIT 8",
    "Government IDs": "SELECT customer_id, ssn, aadhaar_no, pan_no FROM customers ORDER BY customer_id LIMIT 8",
    "Cards joined to customers": (
        "SELECT c.full_name, k.card_number, k.credit_limit FROM customers c "
        "JOIN cards k ON k.customer_id = c.customer_id ORDER BY c.customer_id, k.card_id LIMIT 8"
    ),
    "Account balances": "SELECT account_number, account_type, balance FROM accounts ORDER BY account_id LIMIT 8",
    "Free-text notes": "SELECT customer_id, support_note FROM customers ORDER BY customer_id LIMIT 8",
    "Analytics by account type": "SELECT account_type, COUNT(*) AS accounts, AVG(balance) AS avg_balance FROM accounts GROUP BY account_type",
    "SELECT * on customers": "SELECT * FROM customers ORDER BY customer_id LIMIT 5",
    "Probe attempt (should be denied)": "SELECT customer_id FROM cards WHERE card_number LIKE '4111%'",
    "Write attempt (should be denied)": "DELETE FROM cards WHERE card_id = 1",
}

BANK_PACK = {
    "Contact details": "SELECT customer_id, cust_nm, mob_no, emailid, dob_dt, addr_line1 FROM customers ORDER BY customer_id LIMIT 8",
    "Government IDs": (
        "SELECT k.customer_id, k.pan_no, k.aadhaar_no, i.ssn FROM kyc_records k "
        "LEFT JOIN international_customers i ON i.customer_id = k.customer_id ORDER BY k.customer_id LIMIT 8"
    ),
    "Cards joined to customers": (
        "SELECT c.cust_nm, k.CARD_NO, k.CREDIT_LIMIT FROM customers c "
        "JOIN cards k ON k.CUSTOMER_ID = c.customer_id ORDER BY c.customer_id LIMIT 8"
    ),
    "Account balances": "SELECT account_no, acct_type, curr_bal FROM accounts ORDER BY account_no LIMIT 8",
    "Free-text support tickets": "SELECT ticket_id, ticket_text, notes FROM support_tickets ORDER BY ticket_id LIMIT 6",
    "Analytics by account type": "SELECT acct_type, COUNT(*) AS accounts, AVG(curr_bal) AS avg_balance FROM accounts GROUP BY acct_type",
    "SELECT * on customers": "SELECT * FROM customers ORDER BY customer_id LIMIT 5",
    "Probe attempt (should be denied)": "SELECT customer_id FROM cards WHERE CARD_NO LIKE '4111%'",
    "Write attempt (should be denied)": "DELETE FROM cards WHERE CARD_REF = 'x'",
}


def samples_for(schema: dict) -> dict:
    return BANK_PACK if "kyc_records" in schema else DEMO
