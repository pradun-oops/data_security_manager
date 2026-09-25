"""
modules/data_engine.py
Data engine supporting synthetic generation, CSV ingestion, and SQL database loading.
"""

import os
import random
import sqlite3
from typing import Dict, List, Optional, Union
import pandas as pd

# Expected columns required by downstream security modules
EXPECTED_COLUMNS = [
    "Record_ID",
    "Client_Tenant",
    "Customer_Name",
    "Email_Address",
    "Phone_Number",
    "National_Tax_ID",
    "Credit_Card_PAN",
    "IBAN_Account",
    "Account_Type",
    "Total_Balance_USD",
    "Last_Transaction_Amount",
    "Internal_System_Notes",
]


def _generate_valid_credit_card(prefix: str = "4532") -> str:
    """Generates a Luhn-valid synthetic credit card number."""
    number = [int(d) for d in prefix]
    while len(number) < 15:
        number.append(random.randint(0, 9))

    checksum = 0
    reversed_digits = number[::-1]
    for i, digit in enumerate(reversed_digits):
        if i % 2 == 0:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit

    check_digit = (10 - (checksum % 10)) % 10
    number.append(check_digit)
    raw = "".join(map(str, number))
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def validate_and_normalize_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validates that ingested external data contains necessary attributes.
    Fills missing non-critical columns with placeholders so downstream security
    analyzers don't throw KeyError exceptions.
    """
    clean_df = df.copy()

    # If tenant column is missing, assign a default external tenant
    if "Client_Tenant" not in clean_df.columns:
        clean_df["Client_Tenant"] = "External_Ingested_Tenant"

    # Fill any missing required columns with default empty values
    for col in EXPECTED_COLUMNS:
        if col not in clean_df.columns:
            if "Amount" in col or "Balance" in col:
                clean_df[col] = 0.0
            else:
                clean_df[col] = "N/A"

    return clean_df[EXPECTED_COLUMNS]


# ---------------------------------------------------------------------------
# 1. SYNTHETIC GENERATOR (DEFAULT)
# ---------------------------------------------------------------------------
def generate_financial_records(num_records: int = 50) -> pd.DataFrame:
    """Generates a synthetic financial dataset representing multi-tenant client data."""
    clients = [
        "Apex_Capital_Advisors",
        "Vanguard_Wealth_Management",
        "Zenith_Global_Trust",
    ]
    account_types = ["Institutional_Custody", "High_Net_Worth", "Corporate_Treasury"]
    first_names = ["Arjun", "Elena", "Marcus", "Siddharth", "Chloe", "David"]
    last_names = ["Mehta", "Vance", "Kowalski", "Sharma", "DuPont", "Sterling"]
    domains = ["finconsult.org", "institutional.net", "wealthsecure.io"]

    records: List[Dict] = []

    for i in range(1, num_records + 1):
        client = random.choice(clients)
        fname = random.choice(first_names)
        lname = random.choice(last_names)
        full_name = f"{fname} {lname}"
        email = f"{fname.lower()}.{lname.lower()}{random.randint(10, 99)}@{random.choice(domains)}"
        phone = f"+91-{random.randint(70000, 99999)}-{random.randint(10000, 99999)}"

        pan_chars = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=5))
        pan_digits = f"{random.randint(1000, 9999)}"
        pan_last = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        pan_id = f"{pan_chars}{pan_digits}{pan_last}"

        ssn = f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
        card_num = _generate_valid_credit_card()
        iban = f"GB{random.randint(10, 99)}MIDL401278{random.randint(10000000, 99999999)}"

        balance = round(random.uniform(50000.0, 5000000.0), 2)
        wire_amount = round(random.uniform(1000.0, 750000.0), 2)

        unstructured_templates = [
            f"Routine quarterly audit cleared. Beneficiary card details verified: {card_num}.",
            f"Client requested direct wire transfer of ${wire_amount:,.2f} to account {iban}.",
            f"KYC document update complete. Tax ID verification confirmed with PAN {pan_id}.",
            f"General maintenance review completed for account profile {i}.",
            f"Standard wire routing via secure gateway. Internal reference #{random.randint(100000, 999999)}.",
        ]

        records.append(
            {
                "Record_ID": f"REC-FIN-{i:05d}",
                "Client_Tenant": client,
                "Customer_Name": full_name,
                "Email_Address": email,
                "Phone_Number": phone,
                "National_Tax_ID": pan_id if random.random() > 0.5 else ssn,
                "Credit_Card_PAN": card_num,
                "IBAN_Account": iban,
                "Account_Type": random.choice(account_types),
                "Total_Balance_USD": balance,
                "Last_Transaction_Amount": wire_amount,
                "Internal_System_Notes": random.choice(unstructured_templates),
            }
        )

    return pd.DataFrame(records)


# ---------------------------------------------------------------------------
# 2. EXTERNAL CSV INGESTION
# ---------------------------------------------------------------------------
def load_from_csv(file_source: Union[str, os.PathLike, object]) -> pd.DataFrame:
    """
    Loads data from a local CSV file path or a Streamlit UploadedFile object.
    Applies schema normalization.
    """
    try:
        raw_df = pd.read_csv(file_source)
        return validate_and_normalize_schema(raw_df)
    except Exception as e:
        raise ValueError(f"Failed to ingest CSV data: {str(e)}")


# ---------------------------------------------------------------------------
# 3. SQL DATABASE INGESTION (SQLite / SQLAlchemy)
# ---------------------------------------------------------------------------
def load_from_sqlite(
    db_path: str = "financial_data.db",
    query: str = "SELECT * FROM financial_records",
) -> pd.DataFrame:
    """
    Connects to a local SQLite database, queries records, and normalizes schema.
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file not found at: {db_path}")

    conn = sqlite3.connect(db_path)
    try:
        raw_df = pd.read_sql_query(query, conn)
        return validate_and_normalize_schema(raw_df)
    finally:
        conn.close()


def export_dataframe_to_sqlite(
    df: pd.DataFrame,
    db_path: str = "financial_data.db",
    table_name: str = "financial_records",
):
    """Utility to initialize a SQLite database file with financial records."""
    conn = sqlite3.connect(db_path)
    try:
        df.to_sql(table_name, conn, if_exists="replace", index=False)
    finally:
        conn.close()