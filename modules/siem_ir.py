"""
modules/siem_ir.py
SIEM event correlation, Incident Response (IR) state management, and Risk Register.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List
import pandas as pd


class IncidentSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "UNDER_INVESTIGATION"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


@dataclass
class SecurityIncident:
    incident_id: str
    created_at: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    affected_user: str
    affected_tenant: str
    correlated_events: List[str]
    root_cause: str
    recommended_playbook: str
    containment_actions_taken: List[str] = field(default_factory=list)


class SIEMCorrelationEngine:
    def __init__(self):
        self.raw_logs: List[Dict[str, Any]] = []
        self.incidents: List[SecurityIncident] = []

    def ingest_log(self, source: str, event_data: Dict[str, Any]):
        entry = {
            "log_id": f"LOG-{len(self.raw_logs) + 1:06d}",
            "timestamp": event_data.get(
                "timestamp", datetime.now(timezone.utc).isoformat()
            ),
            "source": source,
            "data": event_data,
        }
        self.raw_logs.append(entry)

    def run_correlation(self) -> List[SecurityIncident]:
        new_incidents = []

        ueba_anomalies = [
            log
            for log in self.raw_logs
            if log["source"] == "UEBA"
            and log["data"].get("Threat_Level")
            in ("CRITICAL_THREAT", "SUSPICIOUS")
        ]

        dlp_violations = [
            log
            for log in self.raw_logs
            if log["source"] == "DLP"
            and log["data"].get("action_taken")
            in ("BLOCKED", "FLAGGED_AUDIT")
        ]

        for ueba in ueba_anomalies:
            target_user = ueba["data"].get("User")
            matching_dlp = [
                d
                for d in dlp_violations
                if d["data"].get("user") == target_user
                or target_user in d["data"].get("user", "")
            ]

            if matching_dlp:
                inc_id = f"INC-SEC-{len(self.incidents) + len(new_incidents) + 101}"
                correlated_ids = [ueba["log_id"]] + [m["log_id"] for m in matching_dlp]

                incident = SecurityIncident(
                    incident_id=inc_id,
                    created_at=datetime.now(timezone.utc).isoformat(),
                    title=f"Coordinated Insider Data Exfiltration Attempt: {target_user}",
                    severity=IncidentSeverity.CRITICAL,
                    status=IncidentStatus.NEW,
                    affected_user=target_user,
                    affected_tenant="Multi-Tenant Environment",
                    correlated_events=correlated_ids,
                    root_cause=(
                        f"Machine learning flagged abnormal activity (Score: {ueba['data'].get('Risk_Score')}) "
                        f"coinciding with DLP inspection alert on channel [{matching_dlp[0]['data'].get('channel')}]."
                    ),
                    recommended_playbook="PLAYBOOK-IR-04: Compromised Credential & Host Isolation",
                )
                new_incidents.append(incident)

        self.incidents.extend(new_incidents)
        return new_incidents

    def apply_containment(self, incident_id: str, action: str) -> bool:
        for inc in self.incidents:
            if inc.incident_id == incident_id:
                now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
                inc.containment_actions_taken.append(f"[{now_str}] {action}")
                inc.status = IncidentStatus.CONTAINED
                return True
        return False


class RiskRegisterManager:
    @staticmethod
    def get_risk_register() -> pd.DataFrame:
        risks = [
            {
                "Risk_ID": "RSK-001",
                "Category": "Data Exfiltration",
                "Threat_Description": "Unauthorized export of PCI card numbers via unmanaged USB / web channels",
                "Inherent_Risk": 9.0,
                "Mitigating_Control": "Endpoint DLP Enforce Mode + USB Block Policy",
                "Residual_Risk": 2.5,
                "Regulatory_Impact": "PCI DSS v4.0 Req 3.4",
                "Status": "MITIGATED",
            },
            {
                "Risk_ID": "RSK-002",
                "Category": "Identity & Tenant Isolation",
                "Threat_Description": "Cross-tenant record leakage by support personnel or misconfigured IAM",
                "Inherent_Risk": 8.5,
                "Mitigating_Control": "Multi-Tenant Dynamic Data Masking + JIT Access Elevation",
                "Residual_Risk": 2.0,
                "Regulatory_Impact": "SOC 2 Type II / DPDP Act",
                "Status": "MITIGATED",
            },
            {
                "Risk_ID": "RSK-003",
                "Category": "Data at Rest",
                "Threat_Description": "Direct database compromise exposing cleartext financial balances and PII",
                "Inherent_Risk": 9.5,
                "Mitigating_Control": "AES-256-GCM Envelope Encryption with Tenant KEK isolation",
                "Residual_Risk": 1.5,
                "Regulatory_Impact": "GLBA / GDPR Art 32",
                "Status": "MITIGATED",
            },
            {
                "Risk_ID": "RSK-004",
                "Category": "Insider Threat",
                "Threat_Description": "Slow-and-low bulk scraping of customer records by authorized insider",
                "Inherent_Risk": 8.0,
                "Mitigating_Control": "Isolation Forest UEBA Real-Time Anomaly Scoring",
                "Residual_Risk": 3.0,
                "Regulatory_Impact": "ISO 27001 A.12.4",
                "Status": "ACTIVE_MONITORING",
            },
        ]
        return pd.DataFrame(risks)


def generate_executive_compliance_summary(siem: SIEMCorrelationEngine) -> Dict[str, Any]:
    total_logs = len(siem.raw_logs)
    total_incidents = len(siem.incidents)
    critical_incidents = len(
        [i for i in siem.incidents if i.severity == IncidentSeverity.CRITICAL]
    )
    contained_incidents = len(
        [i for i in siem.incidents if i.status == IncidentStatus.CONTAINED]
    )

    return {
        "Audit_Date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Overall_Compliance_Posture": "HEALTHY (CONTROLS OPERATIONAL)",
        "Total_Security_Telemetry_Ingested": total_logs,
        "Correlated_Incidents": total_incidents,
        "Critical_Threats": critical_incidents,
        "Automated_Containment_Rate": f"{(contained_incidents / total_incidents * 100) if total_incidents > 0 else 100:.1f}%",
        "Key_Frameworks_Covered": [
            "PCI DSS v4.0",
            "DPDP Act (India)",
            "GDPR",
            "GLBA",
            "SOX",
        ],
    }