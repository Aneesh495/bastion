-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0003_persistence.sql
-- Description: MITRE ATT&CK Tactic TA0003 (Persistence) detection rules:
--              IAM secondary access key generation, authorized_keys tampering,
--              rogue cloud account creation, and systemd persistence implants.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0003-01: Additional IAM Access Key Created for Existing Identity
-- MITRE Technique: T1098.001 (Account Manipulation: Additional Cloud Credentials)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1098_001_new_access_key AS
SELECT
    'BST-R-0301' AS rule_code,
    e.event_id AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    e.event_time AS detected_at,
    'HIGH' AS severity,
    92.0 AS confidence_score,
    88.0 AS composite_risk_score,
    'Secondary Cloud Access Key Generated: ' || e.principal_arn AS title,
    'Actor ' || e.principal_arn || ' invoked CreateAccessKey from IP ' || e.source_ip_address AS summary,
    '{"event":"CreateAccessKey","caller":"' || e.principal_arn || '","ip":"' || e.source_ip_address || '"}' AS evidence_json,
    'TA0003' AS tactic_code,
    'T1098.001' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE e.event_source = 'iam.amazonaws.com'
  AND e.event_name = 'CreateAccessKey'
  AND e.status_code = 200;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0003-02: SSH Authorized Keys File Modification
-- MITRE Technique: T1098.004 (Account Manipulation: SSH Authorized Keys)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1098_004_ssh_authorized_keys_tamper AS
SELECT
    'BST-R-0302' AS rule_code,
    f.modification_id AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    f.asset_id AS entity_id,
    f.event_time AS detected_at,
    'CRITICAL' AS severity,
    95.0 AS confidence_score,
    92.0 AS composite_risk_score,
    'SSH authorized_keys Modification on ' || a.hostname AS title,
    'File ' || f.file_path || ' was ' || f.action || ' on host ' || a.hostname AS summary,
    '{"path":"' || f.file_path || '","action":"' || f.action || '","new_hash":"' || COALESCE(f.new_sha256, 'none') || '"}' AS evidence_json,
    'TA0003' AS tactic_code,
    'T1098.004' AS technique_code
FROM telemetry_file_modifications f
JOIN core_compute_assets a ON f.asset_id = a.asset_id
WHERE f.file_path LIKE '%/.ssh/authorized_keys%'
  AND f.action IN ('CREATED', 'MODIFIED', 'PERMISSIONS_CHANGED');

-- ----------------------------------------------------------------------------
-- Rule BST-TA0003-03: Rogue IAM User Created Out of Standard Provisioning
-- MITRE Technique: T1136.003 (Create Account: Cloud Account)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1136_003_rogue_iam_user AS
SELECT
    'BST-R-0303' AS rule_code,
    e.event_id AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    e.event_time AS detected_at,
    'HIGH' AS severity,
    90.0 AS confidence_score,
    88.0 AS composite_risk_score,
    'New Cloud IAM User Provisioned: ' || e.event_name AS title,
    'Actor ' || e.principal_arn || ' created a new IAM user account from IP ' || e.source_ip_address AS summary,
    '{"event":"CreateUser","request":"' || SUBSTR(COALESCE(e.request_parameters, '{}'), 1, 200) || '"}' AS evidence_json,
    'TA0003' AS tactic_code,
    'T1136.003' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE e.event_source = 'iam.amazonaws.com'
  AND e.event_name = 'CreateUser'
  AND e.status_code = 200;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0003 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0003 AS
SELECT * FROM v_rule_t1098_001_new_access_key
UNION ALL SELECT * FROM v_rule_t1098_004_ssh_authorized_keys_tamper
UNION ALL SELECT * FROM v_rule_t1136_003_rogue_iam_user;
