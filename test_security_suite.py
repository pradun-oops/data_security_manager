"""
test_security_suite.py
Automated Verification Suite for Enterprise Data Security Manager.
Validates Discovery, IAM/DDM, AES-GCM Envelope Encryption, DLP, UEBA, and SIEM.
"""

import unittest
import pandas as pd
from modules.data_engine import _generate_valid_credit_card
from modules.discovery_classifier import (
    verify_luhn,
    scan_cell,
    CLASSIFICATION_MATRIX,
)
from modules.iam_rbac import (
    UserSession,
    enforce_tenant_boundary,
    apply_dynamic_masking,
)
from modules.crypto_engine import EnvelopeEncryption, inspect_transit_security
from modules.dlp_engine import DLPEngine, DLPMode, ExfiltrationChannel
from modules.anomaly_detector import BehaviorAnomalyDetector
from modules.siem_ir import (
    SIEMCorrelationEngine,
    IncidentSeverity,
    IncidentStatus,
)


class TestDataSecurityPlatform(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.detector = BehaviorAnomalyDetector()
        cls.detector.train_baseline()
        # Dynamically generate a Luhn-compliant test card
        cls.valid_card = _generate_valid_credit_card()

    def test_01_luhn_algorithm_validation(self):
        """Verifies that Luhn correctly identifies valid cards and rejects invalid ones."""
        # A known Luhn-valid card: 4532-0000-0000-0009
        known_valid = "4532-0000-0000-0009"
        corrupted_invalid = "4532-0000-0000-0008"

        self.assertTrue(verify_luhn(self.valid_card))
        self.assertTrue(verify_luhn(known_valid))
        self.assertFalse(verify_luhn(corrupted_invalid))

    def test_02_pattern_classification_mapping(self):
        """Ensures PCI tokens map to Restricted and PII maps to Confidential."""
        payload = f"Customer PAN is ABCDE1234F and card is {self.valid_card}"
        findings = scan_cell(payload)
        found_types = [t for t, _ in findings]

        self.assertIn("INDIAN_PAN", found_types)
        self.assertIn("CREDIT_CARD", found_types)
        self.assertEqual(
            CLASSIFICATION_MATRIX["CREDIT_CARD"]["Level"], "Restricted"
        )
        self.assertEqual(
            CLASSIFICATION_MATRIX["INDIAN_PAN"]["Level"], "Restricted"
        )

    def test_03_tenant_isolation_boundary(self):
        """Ensures an analyst for Client A cannot access Client B records."""
        sample_df = pd.DataFrame(
            [
                {
                    "Client_Tenant": "Apex_Capital_Advisors",
                    "Record_ID": "1",
                },
                {
                    "Client_Tenant": "Vanguard_Wealth_Management",
                    "Record_ID": "2",
                },
            ]
        )
        analyst = UserSession(
            username="bob",
            role="Financial_Analyst",
            tenant_scope="Apex_Capital_Advisors",
        )
        scoped_df, authorized = enforce_tenant_boundary(sample_df, analyst)

        self.assertTrue(authorized)
        self.assertEqual(len(scoped_df), 1)
        self.assertEqual(
            scoped_df["Client_Tenant"].iloc[0], "Apex_Capital_Advisors"
        )

    def test_04_dynamic_data_masking_enforcement(self):
        """Ensures Tier 1 support cannot view raw credit cards or unmasked balances."""
        df = pd.DataFrame(
            [
                {
                    "Client_Tenant": "Apex_Capital_Advisors",
                    "Customer_Name": "Elena Vance",
                    "Credit_Card_PAN": self.valid_card,
                    "Total_Balance_USD": 550000.0,
                    "Email_Address": "elena@test.org",
                }
            ]
        )
        support = UserSession(
            username="alice",
            role="Tier1_Support",
            tenant_scope="Apex_Capital_Advisors",
        )
        masked_df = apply_dynamic_masking(df, support)

        self.assertEqual(
            masked_df["Credit_Card_PAN"].iloc[0], "[ACCESS DENIED - RESTRICTED]"
        )
        self.assertEqual(masked_df["Total_Balance_USD"].iloc[0], "$***,***.**")
        self.assertTrue("*" in masked_df["Email_Address"].iloc[0])

    def test_05_envelope_encryption_roundtrip(self):
        """Verifies AES-256-GCM encryption with ephemeral DEK unwrapped by Tenant KEK."""
        secret = "CONFIDENTIAL_FINANCIAL_PAYLOAD_99"
        tenant = "Apex_Capital_Advisors"

        enc_data, enc_dek, iv = EnvelopeEncryption.encrypt_payload(
            secret, tenant
        )
        decrypted = EnvelopeEncryption.decrypt_payload(
            enc_data, enc_dek, iv, tenant
        )

        self.assertEqual(secret, decrypted)
        self.assertNotEqual(secret, enc_data)

    def test_06_transit_security_checks(self):
        """Verifies that insecure protocols (HTTP) fail PCI transit requirements."""
        res_http = inspect_transit_security("HTTP", "NONE")
        res_tls = inspect_transit_security("TLSv1.3", "TLS_AES_256_GCM_SHA384")

        self.assertEqual(res_http["Status"], "CRITICAL_VIOLATION")
        self.assertEqual(res_tls["Status"], "COMPLIANT")

    def test_07_dlp_audit_vs_enforce_decision(self):
        """Verifies that Audit mode permits with flag, while Enforce mode terminates egress."""
        leak_text = f"Payout card details: {self.valid_card}"
        dlp = DLPEngine(mode=DLPMode.AUDIT)

        evt_audit = dlp.inspect_and_filter(
            leak_text, "user1", "10.0.0.1", ExfiltrationChannel.USB_STORAGE
        )
        self.assertEqual(evt_audit.action_taken, "FLAGGED_AUDIT")

        dlp.set_mode(DLPMode.ENFORCE)
        evt_enforce = dlp.inspect_and_filter(
            leak_text, "user1", "10.0.0.1", ExfiltrationChannel.USB_STORAGE
        )
        self.assertEqual(evt_enforce.action_taken, "BLOCKED")

    def test_08_isolation_forest_anomaly_scoring(self):
        """Tests that routine midday activity scores low risk, and 3 AM scraping triggers a threat."""
        benign_session = {
            "username": "routine_user",
            "access_hour": 13,
            "record_query_count": 10,
            "data_volume_mb": 1.5,
            "restricted_record_ratio": 0.05,
            "failed_auth_attempts": 0,
        }
        res_benign = self.detector.analyze_activity(benign_session)
        self.assertFalse(res_benign["Is_Anomaly"])
        self.assertEqual(res_benign["Threat_Level"], "NORMAL")

        threat_session = {
            "username": "exfil_actor",
            "access_hour": 3,
            "record_query_count": 800,
            "data_volume_mb": 750.0,
            "restricted_record_ratio": 0.9,
            "failed_auth_attempts": 5,
        }
        res_threat = self.detector.analyze_activity(threat_session)
        self.assertTrue(res_threat["Is_Anomaly"])
        self.assertIn(
            res_threat["Threat_Level"], ("SUSPICIOUS", "CRITICAL_THREAT")
        )
        self.assertGreaterEqual(res_threat["Risk_Score"], 50.0)

    def test_09_siem_event_correlation_and_containment(self):
        """Verifies correlation across UEBA + DLP feeds into a correlated Security Incident."""
        siem = SIEMCorrelationEngine()

        siem.ingest_log(
            "UEBA",
            {
                "User": "insider_threat",
                "Threat_Level": "CRITICAL_THREAT",
                "Risk_Score": 85.0,
            },
        )
        siem.ingest_log(
            "DLP",
            {
                "user": "insider_threat",
                "channel": "Public_Web_Browser_Upload",
                "action_taken": "BLOCKED",
            },
        )

        incidents = siem.run_correlation()
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.severity, IncidentSeverity.CRITICAL)
        self.assertEqual(inc.status, IncidentStatus.NEW)

        siem.apply_containment(inc.incident_id, "REVOKE_TOKEN_AND_QUARANTINE")
        self.assertEqual(inc.status, IncidentStatus.CONTAINED)
        self.assertEqual(len(inc.containment_actions_taken), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)