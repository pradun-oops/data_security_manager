"""
modules/iam_rbac.py
Multi-tenant isolation, Role-Based Access Control, and Dynamic Data Masking (DDM).
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import pandas as pd
from modules.discovery_classifier import mask_data, scan_cell


@dataclass
class UserSession:
    username: str
    role: str
    tenant_scope: str  # Specific client name or "ALL_TENANTS"
    mfa_authenticated: bool = True
    jit_elevated: bool = False


# Role Permission Matrix defining field-level access capabilities
ROLE_POLICIES: Dict[str, Dict[str, str]] = {
    "Data_Security_Officer": {
        "Restricted": "UNMASKED" if True else "MASKED",
        "Confidential": "UNMASKED",
        "Internal": "UNMASKED",
        "Cross_Tenant_Access": "TRUE",
        "Can_Export": "TRUE",
    },
    "Compliance_Auditor": {
        "Restricted": "MASKED",
        "Confidential": "MASKED",
        "Internal": "UNMASKED",
        "Cross_Tenant_Access": "TRUE",
        "Can_Export": "FALSE",
    },
    "Financial_Analyst": {
        "Restricted": "REDACTED",  # Completely hidden
        "Confidential": "UNMASKED",  # Financial balances visible
        "Internal": "UNMASKED",
        "Cross_Tenant_Access": "FALSE",  # Strict client boundary
        "Can_Export": "FALSE",
    },
    "Tier1_Support": {
        "Restricted": "REDACTED",
        "Confidential": "MASKED",
        "Internal": "UNMASKED",
        "Cross_Tenant_Access": "FALSE",
        "Can_Export": "FALSE",
    },
}

RESTRICTED_COLUMNS = ["Credit_Card_PAN", "National_Tax_ID", "Internal_System_Notes"]
CONFIDENTIAL_COLUMNS = [
    "IBAN_Account",
    "Email_Address",
    "Phone_Number",
    "Total_Balance_USD",
    "Last_Transaction_Amount",
]


def enforce_tenant_boundary(
    df: pd.DataFrame, session: UserSession
) -> Tuple[pd.DataFrame, bool]:
    """Filters dataset to client tenant scope. Flags cross-tenant boundary violations."""
    if session.tenant_scope == "ALL_TENANTS":
        if (
            ROLE_POLICIES.get(session.role, {}).get("Cross_Tenant_Access")
            != "TRUE"
        ):
            # Unauthorized cross-tenant attempt
            return pd.DataFrame(), False
        return df.copy(), True

    # Filter to authorized client tenant only
    scoped_df = df[df["Client_Tenant"] == session.tenant_scope].copy()
    return scoped_df, True


def apply_dynamic_masking(df: pd.DataFrame, session: UserSession) -> pd.DataFrame:
    """
    Applies column and row-level dynamic masking based on user role and JIT status.
    Prevents unauthorized data exposure at the presentation layer.
    """
    scoped_df, is_authorized = enforce_tenant_boundary(df, session)
    if not is_authorized or scoped_df.empty:
        return scoped_df

    output_df = scoped_df.copy()
    role_policy = ROLE_POLICIES.get(session.role, ROLE_POLICIES["Tier1_Support"])

    restricted_access = role_policy["Restricted"]
    confidential_access = role_policy["Confidential"]

    # JIT Elevation override for security officers
    if session.jit_elevated and session.role == "Data_Security_Officer":
        return output_df

    # Process Restricted columns (PCI / Tax IDs / Freeform notes)
    for col in RESTRICTED_COLUMNS:
        if col in output_df.columns:
            if restricted_access == "REDACTED":
                output_df[col] = "[ACCESS DENIED - RESTRICTED]"
            elif restricted_access == "MASKED":
                if col == "Credit_Card_PAN":
                    output_df[col] = output_df[col].apply(
                        lambda x: mask_data(str(x), "CREDIT_CARD")
                    )
                elif col == "National_Tax_ID":
                    output_df[col] = output_df[col].apply(
                        lambda x: mask_data(str(x), "US_SSN")
                    )
                elif col == "Internal_System_Notes":
                    output_df[col] = (
                        "[NOTE CONTENT MASKED BY POLICY - AUDIT LOGGED]"
                    )

    # Process Confidential columns (PII / Balances / IBAN)
    for col in CONFIDENTIAL_COLUMNS:
        if col in output_df.columns:
            if confidential_access == "MASKED":
                if col == "IBAN_Account":
                    output_df[col] = output_df[col].apply(
                        lambda x: mask_data(str(x), "IBAN")
                    )
                elif col == "Email_Address":
                    output_df[col] = output_df[col].apply(
                        lambda x: mask_data(str(x), "EMAIL")
                    )
                elif col == "Phone_Number":
                    output_df[col] = output_df[col].apply(
                        lambda x: f"{str(x)[:6]}*****"
                    )
                elif col in ["Total_Balance_USD", "Last_Transaction_Amount"]:
                    output_df[col] = "$***,***.**"
            elif confidential_access == "REDACTED":
                output_df[col] = "[REDACTED - PII]"

    return output_df


def audit_access_attempt(
    session: UserSession, resource_requested: str, success: bool
) -> Dict[str, str]:
    """Generates standardized IAM audit record for SIEM ingestion."""
    return {
        "Timestamp": pd.Timestamp.now().isoformat(),
        "User": session.username,
        "Role": session.role,
        "Tenant_Scope": session.tenant_scope,
        "Resource": resource_requested,
        "MFA": "PASS" if session.mfa_authenticated else "FAIL",
        "JIT_Elevation": "ACTIVE" if session.jit_elevated else "INACTIVE",
        "Policy_Decision": "PERMIT" if success else "DENY",
    }