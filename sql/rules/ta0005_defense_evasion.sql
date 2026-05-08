-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0005_defense_evasion.sql
-- Description: MITRE ATT&CK Tactic TA0005 (Defense Evasion) detection rules:
--              CloudTrail disabling, system log purging, security tool tampering,
--              and process path masquerading.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0005-01: CloudTrail Logging Disabled or Deleted
-- MITRE Technique: T1562.001 (Impair Defenses: Disable Cloud Logs)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1562_001_cloudtrail_tamper AS
SELECT
    'BST-R-0501' AS rule_code,
    e.event_id AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    e.event_time AS detected_at,
    'CRITICAL' AS severity,
    100.0 AS confidence_score,
    100.0 AS composite_risk_score,
    'CloudTrail Logging Deactivated: ' || e.event_name AS title,
    'Actor ' || e.principal_arn || ' deactivated or deleted CloudTrail audit logging via ' || e.event_name || ' from IP ' || e.source_ip_address AS summary,
    '{"event":"' || e.event_name || '","actor":"' || e.principal_arn || '","ip":"' || e.source_ip_address || '"}' AS evidence_json,
    'TA0005' AS tactic_code,
    'T1562.001' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE e.event_source = 'cloudtrail.amazonaws.com'
  AND e.event_name IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')
  AND e.status_code = 200;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0005-02: System Audit Log Cleared via CLI
-- MITRE Technique: T1070.001 (Indicator Removal: Clear Windows Event Logs)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1070_001_log_clearing_command AS
SELECT
    'BST-R-0502' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'CRITICAL' AS severity,
    98.0 AS confidence_score,
    96.0 AS composite_risk_score,
    'Audit Log Deletion Command on ' || a.hostname AS title,
    'Process ' || p.process_name || ' executed log clearing commands: ' || SUBSTR(p.command_line, 1, 150) AS summary,
    '{"cmd":"' || SUBSTR(p.command_line, 1, 250) || '","user":"' || p.executing_user || '"}' AS evidence_json,
    'TA0005' AS tactic_code,
    'T1070.001' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    p.command_line LIKE '%wevtutil% cl %' OR
    p.command_line LIKE '%Clear-EventLog%' OR
    p.command_line LIKE '%rm -rf /var/log/%' OR
    p.command_line LIKE '%shred %/var/log%'
);

-- ----------------------------------------------------------------------------
-- Rule BST-TA0005-03: System Process Path Masquerading
-- MITRE Technique: T1036.005 (Masquerading: Match Legitimate Name or Location)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1036_005_process_masquerading AS
SELECT
    'BST-R-0503' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'HIGH' AS severity,
    92.0 AS confidence_score,
    90.0 AS composite_risk_score,
    'Process Path Masquerading on ' || a.hostname AS title,
    'System binary name ' || p.process_name || ' executed from non-standard directory: ' || p.process_path AS summary,
    '{"process":"' || p.process_name || '","path":"' || p.process_path || '","hash":"' || p.hash_sha256 || '"}' AS evidence_json,
    'TA0005' AS tactic_code,
    'T1036.005' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    (LOWER(p.process_name) = 'svchost.exe' AND LOWER(p.process_path) NOT LIKE '%\\windows\\system32\\%') OR
    (LOWER(p.process_name) = 'lsass.exe' AND LOWER(p.process_path) NOT LIKE '%\\windows\\system32\\%') OR
    (LOWER(p.process_name) = 'systemd' AND LOWER(p.process_path) NOT IN ('/lib/systemd/systemd', '/usr/lib/systemd/systemd', '/sbin/init'))
);

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0005 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0005 AS
SELECT * FROM v_rule_t1562_001_cloudtrail_tamper
UNION ALL SELECT * FROM v_rule_t1070_001_log_clearing_command
UNION ALL SELECT * FROM v_rule_t1036_005_process_masquerading;
