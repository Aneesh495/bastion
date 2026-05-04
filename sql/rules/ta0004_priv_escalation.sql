-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0004_priv_escalation.sql
-- Description: MITRE ATT&CK Tactic TA0004 (Privilege Escalation) detection rules:
--              Administrator policy attachment, Sudo abuse, and SUID elevation.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0004-01: Administrator Policy Attached to Identity
-- MITRE Technique: T1078.004 (Valid Accounts: Cloud Accounts)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1078_admin_policy_attached AS
SELECT
    'BST-R-0401' AS rule_code,
    e.event_id AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    e.event_time AS detected_at,
    'CRITICAL' AS severity,
    98.0 AS confidence_score,
    98.0 AS composite_risk_score,
    'Privileged Policy Attachment: ' || e.event_name AS title,
    'Actor ' || e.principal_arn || ' attached an administrative policy (' || COALESCE(e.request_parameters, 'policy') || ') to target identity' AS summary,
    '{"event":"' || e.event_name || '","actor":"' || e.principal_arn || '","ip":"' || e.source_ip_address || '"}' AS evidence_json,
    'TA0004' AS tactic_code,
    'T1078.004' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE e.event_source = 'iam.amazonaws.com'
  AND e.event_name IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'PutUserPolicy', 'PutRolePolicy')
  AND (e.request_parameters LIKE '%AdministratorAccess%' OR e.request_parameters LIKE '%"*"%')
  AND e.status_code = 200;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0004-02: Sudo / Elevated Root Process Spawned from Low-Integrity Shell
-- MITRE Technique: T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1548_003_sudo_elevation_spawn AS
SELECT
    'BST-R-0402' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'HIGH' AS severity,
    90.0 AS confidence_score,
    88.0 AS composite_risk_score,
    'Elevated Root Execution via Sudo on ' || a.hostname AS title,
    'Process ' || p.process_name || ' executed with root privileges via sudo by non-admin user ' || p.executing_user AS summary,
    '{"cmd":"' || SUBSTR(p.command_line, 1, 200) || '","user":"' || p.executing_user || '"}' AS evidence_json,
    'TA0004' AS tactic_code,
    'T1548.003' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    p.command_line LIKE 'sudo %' OR
    p.command_line LIKE '%su - %' OR
    (p.process_name = 'sudo' AND p.is_elevated = TRUE)
) AND p.executing_user NOT IN ('root', 'system');

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0004 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0004 AS
SELECT * FROM v_rule_t1078_admin_policy_attached
UNION ALL SELECT * FROM v_rule_t1548_003_sudo_elevation_spawn;
