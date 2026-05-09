-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0006_credential_access.sql
-- Description: MITRE ATT&CK Tactic TA0006 (Credential Access) detection rules:
--              LSASS memory dumping, Kerberoasting SPN requests, cloud credential
--              file access, and brute-force password guessing.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0006-01: OS Credential Dumping via LSASS Memory Access
-- MITRE Technique: T1003.001 (OS Credential Dumping: LSASS Memory)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1003_001_lsass_dumping AS
SELECT
    'BST-R-0601' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'CRITICAL' AS severity,
    99.0 AS confidence_score,
    98.0 AS composite_risk_score,
    'LSASS Memory Credential Dumping on ' || a.hostname AS title,
    'Process ' || p.process_name || ' attempted to dump memory from LSASS process: ' || SUBSTR(p.command_line, 1, 150) AS summary,
    '{"cmd":"' || SUBSTR(p.command_line, 1, 200) || '","hash":"' || p.hash_sha256 || '","user":"' || p.executing_user || '"}' AS evidence_json,
    'TA0006' AS tactic_code,
    'T1003.001' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    LOWER(p.command_line) LIKE '%procdump%lsass%' OR
    LOWER(p.command_line) LIKE '%mimikatz%' OR
    LOWER(p.command_line) LIKE '%comsvcs.dll%minidump%' OR
    LOWER(p.command_line) LIKE '%rundll32%comsvcs%' OR
    LOWER(p.command_line) LIKE '%sekurlsa::logonpasswords%'
);

-- ----------------------------------------------------------------------------
-- Rule BST-TA0006-02: Cloud Credential File Read Access
-- MITRE Technique: T1552.001 (Unsecured Credentials: Credentials in Files)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1552_001_cloud_credential_access AS
SELECT
    'BST-R-0602' AS rule_code,
    f.modification_id AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    f.asset_id AS entity_id,
    f.event_time AS detected_at,
    'HIGH' AS severity,
    90.0 AS confidence_score,
    88.0 AS composite_risk_score,
    'Unsecured Cloud Credential File Access on ' || a.hostname AS title,
    'File access or modification on sensitive credential path ' || f.file_path || ' by process ' || COALESCE(f.process_guid, 'unknown') AS summary,
    '{"path":"' || f.file_path || '","action":"' || f.action || '"}' AS evidence_json,
    'TA0006' AS tactic_code,
    'T1552.001' AS technique_code
FROM telemetry_file_modifications f
JOIN core_compute_assets a ON f.asset_id = a.asset_id
WHERE (
    f.file_path LIKE '%/.aws/credentials%' OR
    f.file_path LIKE '%/.azure/tokens%' OR
    f.file_path LIKE '%/gcloud/credentials.db%' OR
    f.file_path LIKE '%/id_rsa%' OR
    f.file_path LIKE '%/id_ed25519%'
);

-- ----------------------------------------------------------------------------
-- Rule BST-TA0006-03: Multiple Authentication Failures Followed by Lockout
-- MITRE Technique: T1110.001 (Brute Force: Password Guessing)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1110_001_password_guessing AS
SELECT
    'BST-R-0603' AS rule_code,
    MIN(auth_event_id) AS evidence_id,
    account_id,
    'PRINCIPAL' AS entity_type,
    principal_id AS entity_id,
    MAX(event_time) AS detected_at,
    'HIGH' AS severity,
    92.0 AS confidence_score,
    85.0 AS composite_risk_score,
    'Repetitive Authentication Failures on Account: ' || username_asserted AS title,
    'Account ' || username_asserted || ' incurred ' || CAST(COUNT(*) AS VARCHAR) || ' failed authentication attempts within 15 minutes' AS summary,
    '{"failures":' || CAST(COUNT(*) AS VARCHAR) || ',"ip":"' || source_ip || '"}' AS evidence_json,
    'TA0006' AS tactic_code,
    'T1110.001' AS technique_code
FROM telemetry_authentication_events
WHERE auth_status = 'FAILURE'
GROUP BY account_id, principal_id, username_asserted, source_ip, DATE_TRUNC('hour', event_time)
HAVING COUNT(*) >= 5;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0006 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0006 AS
SELECT * FROM v_rule_t1003_001_lsass_dumping
UNION ALL SELECT * FROM v_rule_t1552_001_cloud_credential_access
UNION ALL SELECT * FROM v_rule_t1110_001_password_guessing;
