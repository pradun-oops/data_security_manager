"""
app.py
Data Security Manager - Multi-Tenant Financial Services Platform
Central Security Operations, Governance & Incident Response Console
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from modules.data_engine import (
    generate_financial_records,
    load_from_csv,
    load_from_sqlite,
    export_dataframe_to_sqlite,
)
from modules.discovery_classifier import (
    run_discovery_pipeline,
    scan_cell,
    mask_data,
    CLASSIFICATION_MATRIX,
)
from modules.iam_rbac import UserSession, apply_dynamic_masking, ROLE_POLICIES
from modules.crypto_engine import (
    EnvelopeEncryption,
    encrypt_sensitive_dataset,
    inspect_transit_security,
    kms_vault,
)
from modules.dlp_engine import DLPEngine, DLPMode, ExfiltrationChannel
from modules.anomaly_detector import BehaviorAnomalyDetector
from modules.siem_ir import (
    SIEMCorrelationEngine,
    RiskRegisterManager,
    generate_executive_compliance_summary,
    IncidentSeverity,
    IncidentStatus,
)

# -------------------------------------------------------------
# PAGE CONFIGURATION & STATE INITIALIZATION
# -------------------------------------------------------------
st.set_page_config(
    page_title="Data Security Manager | Financial Services",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if "raw_data" not in st.session_state:
    st.session_state.raw_data = generate_financial_records(40)

if "data_source" not in st.session_state:
    st.session_state.data_source = "Synthetic Generator"

if "dlp_engine" not in st.session_state:
    st.session_state.dlp_engine = DLPEngine(mode=DLPMode.AUDIT)

if "anomaly_detector" not in st.session_state:
    detector = BehaviorAnomalyDetector()
    detector.train_baseline()
    st.session_state.anomaly_detector = detector

if "siem" not in st.session_state:
    st.session_state.siem = SIEMCorrelationEngine()

# -------------------------------------------------------------
# SIDEBAR CONTROLS: DATA SOURCE, IDENTITY & POSTURE
# -------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("Security Posture")
    st.caption("Financial Tenant Data Protection Manager")

    st.markdown("---")
    st.subheader("📂 Ingestion & Data Source")

    source_type = st.radio(
        "Active Data Backend",
        options=["Synthetic Generator", "Upload CSV File", "Local SQLite Database"],
        index=0,
    )

    if source_type == "Synthetic Generator":
        if st.button("🔄 Regenerate Dataset", use_container_width=True):
            st.session_state.raw_data = generate_financial_records(40)
            st.session_state.data_source = "Synthetic Generator (40 records)"
            st.success("Generated new client financial dataset.")
            st.rerun()

    elif source_type == "Upload CSV File":
        uploaded_file = st.file_uploader(
            "Upload Client Financial CSV",
            type=["csv"],
            help="Upload a CSV with financial records to scan and protect.",
        )
        if uploaded_file is not None:
            try:
                st.session_state.raw_data = load_from_csv(uploaded_file)
                st.session_state.data_source = f"CSV: {uploaded_file.name}"
                st.success(f"Ingested {len(st.session_state.raw_data)} records!")
            except Exception as err:
                st.error(f"Error parsing CSV: {err}")

    elif source_type == "Local SQLite Database":
        db_path = st.text_input("SQLite DB Path", value="financial_data.db")
        sql_query = st.text_input(
            "SQL Query", value="SELECT * FROM financial_records"
        )
        col_sql1, col_sql2 = st.columns(2)
        with col_sql1:
            if st.button("Query DB", use_container_width=True):
                try:
                    st.session_state.raw_data = load_from_sqlite(db_path, sql_query)
                    st.session_state.data_source = f"SQLite ({db_path})"
                    st.success(f"Loaded {len(st.session_state.raw_data)} rows!")
                    st.rerun()
                except Exception as err:
                    st.error(f"DB Error: {err}")
        with col_sql2:
            if st.button("Seed Demo DB", use_container_width=True):
                seed_df = generate_financial_records(60)
                export_dataframe_to_sqlite(seed_df, db_path)
                st.info(f"Seeded '{db_path}' with 60 records.")

    st.markdown("---")
    st.subheader("🔑 Active Identity Session")

    current_role = st.selectbox(
        "Simulated IAM Role",
        options=[
            "Data_Security_Officer",
            "Compliance_Auditor",
            "Financial_Analyst",
            "Tier1_Support",
        ],
        index=0,
    )

    # Dynamic tenant discovery based on loaded data
    available_tenants = list(st.session_state.raw_data["Client_Tenant"].unique())
    if ROLE_POLICIES[current_role]["Cross_Tenant_Access"] == "TRUE":
        tenant_options = ["ALL_TENANTS"] + available_tenants
    else:
        tenant_options = available_tenants if available_tenants else ["External_Ingested_Tenant"]

    current_tenant = st.selectbox("Tenant Scope", options=tenant_options, index=0)

    jit_elevation = False
    if current_role == "Data_Security_Officer":
        jit_elevation = st.checkbox("Privileged JIT Elevation (PAM)", value=False)

    user_session = UserSession(
        username="sec_ops_admin",
        role=current_role,
        tenant_scope=current_tenant,
        jit_elevated=jit_elevation,
    )

    st.markdown("---")
    st.subheader("🛡️ Global DLP Mode")
    dlp_mode_toggle = st.radio(
        "Policy Enforcement Mode",
        options=["AUDIT", "ENFORCE"],
        index=0 if st.session_state.dlp_engine.mode == DLPMode.AUDIT else 1,
        help="AUDIT logs violations without blocking; ENFORCE actively blocks unauthorized egress.",
    )
    st.session_state.dlp_engine.set_mode(
        DLPMode.AUDIT if dlp_mode_toggle == "AUDIT" else DLPMode.ENFORCE
    )

# -------------------------------------------------------------
# APPLICATION HEADER & TOP-LEVEL METRICS
# -------------------------------------------------------------
st.title("Enterprise Data Security Management Platform")
st.markdown(
    "Unified Data Discovery, Dynamic Masking, Cryptography, DLP, UEBA Anomaly Detection & Incident Response."
)

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Client Records", len(st.session_state.raw_data))
with col2:
    st.metric("Active DLP Mode", st.session_state.dlp_engine.mode.value)
with col3:
    st.metric("SIEM Telemetry Logs", len(st.session_state.siem.raw_logs))
with col4:
    st.metric("Active Incidents", len(st.session_state.siem.incidents))

st.markdown("---")

# -------------------------------------------------------------
# MAIN NAVIGATION TABS
# -------------------------------------------------------------
tab_discovery, tab_rbac, tab_crypto, tab_dlp, tab_ueba, tab_siem = st.tabs(
    [
        "🔍 Data Discovery & Classification",
        "👤 Multi-Tenant RBAC & DDM",
        "🔐 Cryptography & KMS",
        "🚫 DLP Policy & Inspection",
        "🤖 AI/ML Anomaly Detection",
        "🚨 SIEM, Incidents & Governance",
    ]
)

# -------------------------------------------------------------
# TAB 1: DATA DISCOVERY & CLASSIFICATION
# -------------------------------------------------------------
with tab_discovery:
    st.header("Automated Data Discovery & Classification Matrix")
    st.caption(
        "Identifies PCI card numbers (Luhn verified), Tax IDs (PAN/SSN), PII, and financial balances across tenant datasets."
    )

    catalog_df = run_discovery_pipeline(st.session_state.raw_data)

    c1, c2 = st.columns([2, 1])
    with c1:
        st.subheader("Data Asset Inventory Catalog")
        st.dataframe(
            catalog_df[
                [
                    "Asset_Column",
                    "Detected_Type",
                    "Sensitivity_Tier",
                    "Compliance_Framework",
                    "Recommended_Control",
                    "Sample_Masked",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

    with c2:
        st.subheader("Sensitivity Distribution")
        fig = px.pie(
            catalog_df,
            names="Sensitivity_Tier",
            title="Classification Tier Breakdown",
            color="Sensitivity_Tier",
            color_discrete_map={
                "Restricted": "#EF4444",
                "Confidential": "#F59E0B",
                "Internal": "#3B82F6",
            },
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("Interactive Payload Inspector")
    sample_text = st.text_input(
        "Test discovery against arbitrary string or system note payload:",
        value="Beneficiary wire verification cleared using card 4532-0000-0000-0009 and PAN ABCDE1234F.",
    )
    if sample_text:
        findings = scan_cell(sample_text)
        if findings:
            for f_type, token in findings:
                meta = CLASSIFICATION_MATRIX.get(f_type, {})
                st.success(
                    f"**Detected:** `{f_type}` | **Tier:** `{meta.get('Level')}` | "
                    f"**Framework:** `{meta.get('Regulation')}` | **Masked Output:** `{mask_data(token, f_type)}`"
                )
        else:
            st.info("No sensitive financial tokens detected in string.")

# -------------------------------------------------------------
# TAB 2: MULTI-TENANT RBAC & DYNAMIC MASKING (DDM)
# -------------------------------------------------------------
with tab_rbac:
    st.header("Tenant Isolation & Dynamic Data Masking (DDM)")
    st.markdown(
        f"**Active Session Profile:** `{user_session.username}` | "
        f"**Assigned Role:** `{user_session.role}` | "
        f"**Tenant Boundary:** `{user_session.tenant_scope}` | "
        f"**JIT Privileged Status:** `{'ACTIVE' if user_session.jit_elevated else 'INACTIVE'}`"
    )

    rendered_df = apply_dynamic_masking(st.session_state.raw_data, user_session)

    if rendered_df.empty:
        st.error(
            "Access Denied: Current IAM Role does not hold cross-tenant privileges to view global data."
        )
    else:
        st.dataframe(rendered_df, use_container_width=True, hide_index=True)

    with st.expander("ℹ️ Role-Based Access Control Policy Specifications"):
        st.table(pd.DataFrame(ROLE_POLICIES).T)

# -------------------------------------------------------------
# TAB 3: CRYPTOGRAPHY & KEY MANAGEMENT (KMS)
# -------------------------------------------------------------
with tab_crypto:
    st.header("Cryptographic Protections (At Rest & In Transit)")

    col_rest, col_transit = st.columns(2)

    with col_rest:
        st.subheader("Data at Rest: AES-256-GCM Envelope Encryption")
        st.caption(
            "Encrypts payload with ephemeral DEK; DEK wrapped with tenant-isolated Master KEK."
        )

        test_payload = st.text_input(
            "Raw Secret Payload to Encrypt", "4532-0000-0000-0009"
        )
        target_tenant = st.selectbox(
            "Target Tenant KMS Partition",
            options=available_tenants if available_tenants else ["Default_KMS_Tenant"],
            key="crypto_tenant_select",
        )

        if st.button("Execute Envelope Encryption"):
            enc_data, enc_dek, iv = EnvelopeEncryption.encrypt_payload(
                test_payload, target_tenant
            )
            st.code(
                f"Ciphertext (Payload): {enc_data}\nWrapped DEK (KMS Key): {enc_dek}\nIV / Nonce (96-bit): {iv}",
                language="text",
            )
            decrypted = EnvelopeEncryption.decrypt_payload(
                enc_data, enc_dek, iv, target_tenant
            )
            st.success(f"Decryption Verified via Tenant KEK: {decrypted}")

        st.markdown("---")
        if st.button("Simulate Annual Tenant KEK Rotation"):
            kms_vault.rotate_tenant_kek(target_tenant)
            st.warning(
                f"Tenant Master KEK for [{target_tenant}] rotated in KMS. Old DEKs re-wrapped."
            )

    with col_transit:
        st.subheader("Data in Transit: Protocol & Cipher Audit")
        proto = st.selectbox(
            "Protocol Version", ["TLSv1.3", "TLSv1.2", "TLSv1.0", "HTTP"]
        )
        cipher = st.selectbox(
            "Negotiated Cipher Suite",
            [
                "TLS_AES_256_GCM_SHA384",
                "ECDHE-RSA-AES256-GCM-SHA384",
                "RC4-MD5-DEPRECATED",
                "NONE",
            ],
        )

        eval_res = inspect_transit_security(proto, cipher)
        if eval_res["Status"] == "COMPLIANT":
            st.success(f"Status: {eval_res['Status']} - {eval_res['Findings'][0]}")
        elif eval_res["Status"] == "CRITICAL_VIOLATION":
            st.error(f"Status: {eval_res['Status']} - {eval_res['Findings'][0]}")
        else:
            st.warning(f"Status: {eval_res['Status']} - {eval_res['Findings'][0]}")

# -------------------------------------------------------------
# TAB 4: DATA LOSS PREVENTION (DLP)
# -------------------------------------------------------------
with tab_dlp:
    st.header("Data Loss Prevention (DLP) Simulation Bench")
    st.markdown(
        f"**Active Operational Mode:** `{st.session_state.dlp_engine.mode.value}` "
        f"*(Switch mode using sidebar controls)*"
    )

    cd1, cd2 = st.columns([1, 1])
    with cd1:
        sim_user = st.text_input(
            "Originating User / Identity", value="contractor_eva@external.com"
        )
        sim_ip = st.text_input("Source IP", value="192.168.1.185")
        sim_channel = st.selectbox(
            "Exfiltration Channel Vector",
            options=list(ExfiltrationChannel),
            format_func=lambda x: x.value,
        )
        sim_payload = st.text_area(
            "Transmission Content Payload",
            value="Urgent payout required. Transfer funds for card 4532-0000-0000-0009.",
            height=100,
        )

        if st.button("Inspect Transmission Vector", use_container_width=True):
            event = st.session_state.dlp_engine.inspect_and_filter(
                payload_content=sim_payload,
                user=sim_user,
                source_ip=sim_ip,
                channel=sim_channel,
            )
            st.session_state.siem.ingest_log("DLP", event.__dict__)

            if event.action_taken == "BLOCKED":
                st.error(f"🛑 {event.action_taken}: {event.justification}")
            elif event.action_taken == "FLAGGED_AUDIT":
                st.warning(f"⚠️ {event.action_taken}: {event.justification}")
            else:
                st.success(f"✅ {event.action_taken}: {event.justification}")

    with cd2:
        st.subheader("DLP Audit & Inspection Log")
        events = st.session_state.dlp_engine.get_audit_trail()
        if events:
            evt_df = pd.DataFrame(events)
            st.dataframe(
                evt_df[
                    [
                        "event_id",
                        "user",
                        "channel",
                        "policy_mode",
                        "action_taken",
                        "max_severity",
                    ]
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No DLP events recorded yet in current session.")

# -------------------------------------------------------------
# TAB 5: AI/ML ANOMALY DETECTION (UEBA)
# -------------------------------------------------------------
with tab_ueba:
    st.header("AI/ML Behavioral Anomaly Detection (UEBA)")
    st.caption(
        "Unsupervised Isolation Forest model detecting insider threats, off-hours spikes, and bulk exfiltration."
    )

    cu1, cu2 = st.columns([1, 1])
    with cu1:
        st.subheader("Simulate User Activity Session")
        u_name = st.text_input("User Entity", "analyst_bob")
        u_hour = st.slider(
            "Access Time (Hour of Day 0-23)",
            0,
            23,
            14,
            help="Typical hours: 08-18. Off-hours: 22-05.",
        )
        u_queries = st.slider(
            "Record Query Count",
            1,
            1000,
            15,
            help="Typical count: 5-50. Bulk scrape: >150.",
        )
        u_vol = st.slider(
            "Egress Volume (MB)",
            0.1,
            1000.0,
            5.0,
            help="Typical volume: <20MB.",
        )
        u_ratio = st.slider(
            "Restricted Record Query Ratio",
            0.0,
            1.0,
            0.1,
            help="Percentage of queries containing PCI/Tax IDs.",
        )
        u_auth_fail = st.slider(
            "Preceding Failed Auth Probes",
            0,
            10,
            0,
            help="Multiple failed logins before access.",
        )

        if st.button("Run ML Anomaly Analysis", use_container_width=True):
            session_data = {
                "username": u_name,
                "access_hour": u_hour,
                "record_query_count": u_queries,
                "data_volume_mb": u_vol,
                "restricted_record_ratio": u_ratio,
                "failed_auth_attempts": u_auth_fail,
            }
            res = st.session_state.anomaly_detector.analyze_activity(session_data)
            st.session_state.siem.ingest_log("UEBA", res)
            st.session_state.latest_ueba_res = res

    with cu2:
        st.subheader("Model Decision & Risk Scoring")
        if "latest_ueba_res" in st.session_state:
            res = st.session_state.latest_ueba_res
            risk = res["Risk_Score"]

            fig_gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=risk,
                    title={"text": f"Threat Level: {res['Threat_Level']}"},
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {
                            "color": "#EF4444"
                            if risk >= 75
                            else ("#F59E0B" if risk >= 50 else "#10B981")
                        },
                        "steps": [
                            {"range": [0, 30], "color": "#E5E7EB"},
                            {"range": [30, 70], "color": "#FEF3C7"},
                            {"range": [70, 100], "color": "#FEE2E2"},
                        ],
                    },
                )
            )
            fig_gauge.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=20))
            st.plotly_chart(fig_gauge, use_container_width=True)

            st.write("**Identified Anomalous Indicators:**")
            for ind in res["Anomalous_Indicators"]:
                st.markdown(f"- `{ind}`")
        else:
            st.info("Execute user session evaluation to view model scores.")

# -------------------------------------------------------------
# TAB 6: SIEM, INCIDENT RESPONSE & GOVERNANCE
# -------------------------------------------------------------
with tab_siem:
    st.header("Security Operations (SIEM), Incident Response & Risk Register")

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        if st.button("⚡ Correlate Events", use_container_width=True):
            new_inc = st.session_state.siem.run_correlation()
            if new_inc:
                st.success(f"Generated {len(new_inc)} correlated incident(s)!")
            else:
                st.info("No multi-vector correlation triggers met.")

    st.subheader("Active Security Incidents")
    if st.session_state.siem.incidents:
        for inc in st.session_state.siem.incidents:
            with st.expander(
                f"[{inc.severity.value}] {inc.incident_id} - {inc.title} ({inc.status.value})",
                expanded=(inc.status != IncidentStatus.CONTAINED),
            ):
                st.write(f"**Root Cause:** {inc.root_cause}")
                st.write(f"**Recommended Playbook:** `{inc.recommended_playbook}`")
                st.write(f"**Correlated Log IDs:** `{inc.correlated_events}`")

                if inc.containment_actions_taken:
                    st.write(
                        f"**Executed Playbook Actions:** {inc.containment_actions_taken}"
                    )

                if inc.status != IncidentStatus.CONTAINED:
                    if st.button(
                        f"Execute Containment Playbook for {inc.incident_id}"
                    ):
                        st.session_state.siem.apply_containment(
                            inc.incident_id,
                            "REVOKE_ACTIVE_SESSIONS_AND_ISOLATE_HOST",
                        )
                        st.rerun()
    else:
        st.info("Zero open security incidents.")

    st.markdown("---")
    st.subheader("Enterprise Risk Register")
    risk_df = RiskRegisterManager.get_risk_register()
    st.dataframe(risk_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("Executive Management Compliance Summary")
    summary = generate_executive_compliance_summary(st.session_state.siem)
    c_m1, c_m2, c_m3 = st.columns(3)
    c_m1.metric("Compliance Status", summary["Overall_Compliance_Posture"])
    c_m2.metric("Automated Containment Rate", summary["Automated_Containment_Rate"])
    c_m3.metric("Critical Threats", summary["Critical_Threats"])

    with st.expander("📄 Full Compliance Audit Report Payload"):
        st.json(summary)