"""Where each entity SmartMask knows about sits in GDPR and HIPAA.

This is an alignment table for reviewers, not legal advice and not a certification. HIPAA letters refer to the
18 identifiers listed in 45 CFR 164.514(b)(2)(i): A names, B geography below state level, C dates, D phone,
E fax, F email, G SSN, H medical record number, I health plan number, J account numbers, K certificate or licence
numbers, L vehicle IDs, M device IDs, N URLs, O IP addresses, P biometrics, Q photographs, R any other unique ID.
Entities that Saffron Bank does not contain (IP address, medical record number, device ID) are not implemented.
"""

MAPPING = {
    "NAME": ("Personal data (Art. 4(1))", "A names"),
    "ADDRESS": ("Personal data, location (Art. 4(1))", "B geographic subdivisions below state"),
    "PHONE": ("Personal data (Art. 4(1))", "D telephone numbers"),
    "EMAIL": ("Personal data, online identifier (Art. 4(1))", "F email addresses"),
    "DOB": ("Personal data (Art. 4(1))", "C dates related to an individual"),
    "SSN": ("National identification number (Art. 87)", "G social security numbers"),
    "AADHAAR": ("National identification number (Art. 87)", "R other unique identifying number"),
    "PAN": ("Tax identification number (Art. 87)", "R other unique identifying number"),
    "CARD": ("Personal data, financial identifier (Art. 4(1))", "J account numbers"),
    "ACCOUNT_NO": ("Personal data, financial identifier (Art. 4(1))", "J account numbers"),
    "BALANCE": ("Personal data when linked to a person", "Not one of the 18 identifiers"),
    "FREETEXT": ("May hold any personal data", "May hold any of the 18 identifiers"),
}

NOT_IMPLEMENTED = "IP address (O), medical record number (H), health plan number (I), device ID (M), biometrics (P)"


def regulation(entity: str | None) -> tuple[str, str]:
    return MAPPING.get(entity or "", ("-", "-"))
