"""
modules/discovery_classifier.py
Performs regex-based and algorithmic discovery and maps data to a classification matrix.
"""

import re
from typing import Any, Dict, List, Tuple
import pandas as pd


def verify_luhn(card_number_str: str) -> bool:
    """Verifies standard Luhn algorithm for payment cards."""
    digits = [int(d) for d in re.sub(r"\D", "", card_number_str)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reversed_digits = digits[::-1]
    for i, digit in enumerate(reversed_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


# Detection Patterns
PATTERNS = {
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "INDIAN_PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE_INTL": re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,5}\)?[-.\s]?\d{3,5}[-.\s]?\d{4,5}\b"
    ),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
}

# 4-Tier Security Classification Matrix
CLASSIFICATION_MATRIX = {
    "CREDIT_CARD": {
        "Level": "Restricted",
        "Regulation": "PCI DSS v4.0",
        "Risk_Weight": 10,
        "DLP_Action": "Block & Encrypt",
    },
    "INDIAN_PAN": {
        "Level": "Restricted",
        "Regulation": "DPDP / IT Act",
        "Risk_Weight": 9,
        "DLP_Action": "Mask & Audit",
    },
    "US_SSN": {
        "Level": "Restricted",
        "Regulation": "GLBA / Privacy Act",
        "Risk_Weight": 10,
        "DLP_Action": "Block & Encrypt",
    },
    "IBAN": {
        "Level": "Confidential",
        "Regulation": "PCI DSS / Banking Regulations",
        "Risk_Weight": 8,
        "DLP_Action": "Audit & Tokenize",
    },
    "EMAIL": {
        "Level": "Confidential",
        "Regulation": "GDPR / DPDP (PII)",
        "Risk_Weight": 5,
        "DLP_Action": "Audit Mode",
    },
    "PHONE_INTL": {
        "Level": "Confidential",
        "Regulation": "GDPR / DPDP (PII)",
        "Risk_Weight": 5,
        "DLP_Action": "Audit Mode",
    },
    "FINANCIAL_BALANCE": {
        "Level": "Confidential",
        "Regulation": "GLBA / SOX",
        "Risk_Weight": 7,
        "DLP_Action": "RBAC Enforced",
    },
    "INTERNAL_METADATA": {
        "Level": "Internal",
        "Regulation": "Organizational Policy",
        "Risk_Weight": 2,
        "DLP_Action": "Internal Access Only",
    },
}


def mask_data(val: str, pattern_type: str) -> str:
    """Masks discovered data to prevent sensitive leakage during inspection."""
    cleaned = str(val).strip()
    if pattern_type == "CREDIT_CARD":
        digits = re.sub(r"\D", "", cleaned)
        return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "************"
    if pattern_type in ("INDIAN_PAN", "US_SSN"):
        return f"{cleaned[:2]}****{cleaned[-2:]}"
    if pattern_type == "EMAIL":
        parts = cleaned.split("@")
        if len(parts) == 2:
            return f"{parts[0][:2]}***@{parts[1]}"
    if pattern_type == "IBAN":
        return f"{cleaned[:4]}************{cleaned[-4:]}"
    return "********"


def scan_cell(value: Any) -> List[Tuple[str, str]]:
    """Inspects a text or numeric value and flags all matching sensitive data types."""
    results = []
    val_str = str(value)

    if PATTERNS["CREDIT_CARD"].search(val_str):
        matched = PATTERNS["CREDIT_CARD"].search(val_str).group(0)
        if verify_luhn(matched):
            results.append(("CREDIT_CARD", matched))

    if PATTERNS["INDIAN_PAN"].search(val_str):
        matched = PATTERNS["INDIAN_PAN"].search(val_str).group(0)
        results.append(("INDIAN_PAN", matched))

    if PATTERNS["US_SSN"].search(val_str):
        matched = PATTERNS["US_SSN"].search(val_str).group(0)
        results.append(("US_SSN", matched))

    if PATTERNS["IBAN"].search(val_str):
        matched = PATTERNS["IBAN"].search(val_str).group(0)
        results.append(("IBAN", matched))

    if PATTERNS["EMAIL"].search(val_str):
        matched = PATTERNS["EMAIL"].search(val_str).group(0)
        results.append(("EMAIL", matched))

    return results


def run_discovery_pipeline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Automated discovery engine:
    Scans every column and row in the financial dataset, categorizes sensitivity tiers,
    maps compliance obligations, and outputs a Data Inventory & Classification Catalog.
    """
    inventory_rows = []

    for col in df.columns:
        detections = []
        # Sample non-null values for inspection
        sample_vals = df[col].dropna().astype(str).tolist()

        for val in sample_vals:
            findings = scan_cell(val)
            for f_type, raw_match in findings:
                detections.append((f_type, raw_match))

        if detections:
            # Find primary detected sensitive pattern
            type_counts = {}
            for t, _ in detections:
                type_counts[t] = type_counts.get(t, 0) + 1
            primary_type = max(type_counts, key=type_counts.get)
            sample_token = next(m for t, m in detections if t == primary_type)

            meta = CLASSIFICATION_MATRIX.get(primary_type, {})
            inventory_rows.append(
                {
                    "Asset_Column": col,
                    "Detected_Type": primary_type,
                    "Sensitivity_Tier": meta.get("Level", "Internal"),
                    "Compliance_Framework": meta.get("Regulation", "Standard Policy"),
                    "Risk_Weight (1-10)": meta.get("Risk_Weight", 1),
                    "Recommended_Control": meta.get("DLP_Action", "Audit"),
                    "Sample_Masked": mask_data(sample_token, primary_type),
                    "Total_Findings": len(detections),
                }
            )
        else:
            # Heuristic assignment for remaining structured financial columns
            if "Balance" in col or "Amount" in col:
                meta = CLASSIFICATION_MATRIX["FINANCIAL_BALANCE"]
                inventory_rows.append(
                    {
                        "Asset_Column": col,
                        "Detected_Type": "FINANCIAL_BALANCE",
                        "Sensitivity_Tier": meta["Level"],
                        "Compliance_Framework": meta["Regulation"],
                        "Risk_Weight (1-10)": meta["Risk_Weight"],
                        "Recommended_Control": meta["DLP_Action"],
                        "Sample_Masked": "$***,***.**",
                        "Total_Findings": len(df[col]),
                    }
                )
            else:
                meta = CLASSIFICATION_MATRIX["INTERNAL_METADATA"]
                inventory_rows.append(
                    {
                        "Asset_Column": col,
                        "Detected_Type": "METADATA / IDENTIFIER",
                        "Sensitivity_Tier": meta["Level"],
                        "Compliance_Framework": meta["Regulation"],
                        "Risk_Weight (1-10)": meta["Risk_Weight"],
                        "Recommended_Control": meta["DLP_Action"],
                        "Sample_Masked": "NON-PII",
                        "Total_Findings": 0,
                    }
                )

    return pd.DataFrame(inventory_rows)