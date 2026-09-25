"""
modules/dlp_engine.py
Multi-vector Data Loss Prevention (DLP) engine supporting Audit and Enforce operational modes.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List
from modules.discovery_classifier import scan_cell, CLASSIFICATION_MATRIX


class DLPMode(Enum):
    AUDIT = "AUDIT"
    ENFORCE = "ENFORCE"


class ExfiltrationChannel(Enum):
    USB_STORAGE = "USB_Removable_Device"
    EXTERNAL_EMAIL = "External_SMTP_Mail"
    WEB_UPLOAD = "Public_Web_Browser_Upload"
    CLIPBOARD = "Clipboard_Copy_Paste"
    PRINT_SPOOL = "Local_Print_Spooler"
    CLOUD_SYNC = "Unsanctioned_SaaS_Storage"


HIGH_RISK_CHANNELS = {
    ExfiltrationChannel.USB_STORAGE,
    ExfiltrationChannel.EXTERNAL_EMAIL,
    ExfiltrationChannel.WEB_UPLOAD,
    ExfiltrationChannel.CLOUD_SYNC,
}


@dataclass
class DLPEvent:
    event_id: str
    timestamp: str
    user: str
    source_ip: str
    channel: str
    policy_mode: str
    data_findings: List[str]
    max_severity: str
    action_taken: str
    justification: str
    raw_snippet_masked: str


class DLPEngine:
    def __init__(self, mode: DLPMode = DLPMode.AUDIT):
        self.mode = mode
        self.events_log: List[DLPEvent] = []

    def set_mode(self, new_mode: DLPMode):
        self.mode = new_mode

    def inspect_and_filter(
        self,
        payload_content: str,
        user: str,
        source_ip: str,
        channel: ExfiltrationChannel,
        destination: str = "External_Entity",
    ) -> DLPEvent:
        findings = scan_cell(payload_content)
        timestamp = datetime.now(timezone.utc).isoformat()
        event_id = f"DLP-EVT-{len(self.events_log) + 1001}"

        if not findings:
            event = DLPEvent(
                event_id=event_id,
                timestamp=timestamp,
                user=user,
                source_ip=source_ip,
                channel=channel.value,
                policy_mode=self.mode.value,
                data_findings=["NONE"],
                max_severity="Internal",
                action_taken="ALLOWED",
                justification="No sensitive financial tokens detected in transmission.",
                raw_snippet_masked=payload_content[:40],
            )
            self.events_log.append(event)
            return event

        detected_types = [f_type for f_type, _ in findings]
        severities = [
            CLASSIFICATION_MATRIX.get(t, {}).get("Level", "Internal")
            for t in detected_types
        ]

        if "Restricted" in severities:
            highest_tier = "Restricted"
        elif "Confidential" in severities:
            highest_tier = "Confidential"
        else:
            highest_tier = "Internal"

        is_risky_channel = channel in HIGH_RISK_CHANNELS
        is_sensitive = highest_tier in ("Restricted", "Confidential")

        if is_sensitive and is_risky_channel:
            if self.mode == DLPMode.ENFORCE:
                action = "BLOCKED"
                reason = (
                    f"CRITICAL PREVENT: Exfiltration of {highest_tier} tokens "
                    f"via unauthorized channel [{channel.value}] blocked."
                )
            else:
                action = "FLAGGED_AUDIT"
                reason = (
                    f"POLICY VIOLATION OBSERVED: {highest_tier} tokens transferred "
                    f"via [{channel.value}]. Permitted under AUDIT mode."
                )
        else:
            action = "ALLOWED"
            reason = "Activity within acceptable operational policy limits."

        first_token = findings[0][1]
        masked_snippet = f"Content matched pattern [{findings[0][0]}]: {first_token[:4]}****"

        event = DLPEvent(
            event_id=event_id,
            timestamp=timestamp,
            user=user,
            source_ip=source_ip,
            channel=channel.value,
            policy_mode=self.mode.value,
            data_findings=list(set(detected_types)),
            max_severity=highest_tier,
            action_taken=action,
            justification=reason,
            raw_snippet_masked=masked_snippet,
        )

        self.events_log.append(event)
        return event

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return [e.__dict__ for e in self.events_log]