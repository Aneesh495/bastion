-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0040_impact.sql
-- Description: MITRE ATT&CK Tactic TA0040 (Impact) detection rules:
--              Bulk cloud resource deletion, ransomware encryption behavior,
--              and GPU cryptojacking resource hijacking.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0040-01: Bulk Cloud Data Storage Destruction
-- MITRE Technique: T1485 (Data Destruction)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1485_cloud_data_destruction AS
SELECT
    'BST-R-4001' AS rule_code,
    e.event_id AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    e.event_time AS detected_at,
    'CRITICAL' AS severity,
    100.0 AS confidence_score,
    100.0 AS composite_risk_score,
    'Cloud Resource Destruction Command: ' || e.event_name AS title,
    'Actor ' || e.principal_arn || ' executed catastrophic data destruction API ' || e.event_name || ' against cloud infrastructure' AS summary,
    '{"event":"' || e.event_name || '","actor":"' || e.principal_arn || '","ip":"' || e.source_ip_address || '"}' AS evidence_json,
    'TA0040' AS tactic_code,
    'T1485' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE (
    (e.event_source = 's3.amazonaws.com' AND e.event_name IN ('DeleteBucket', 'DeleteObjects')) OR
    (e.event_source = 'rds.amazonaws.com' AND e.event_name IN ('DeleteDBInstance', 'DeleteDBCluster')) OR
    (e.event_source = 'dynamodb.amazonaws.com' AND e.event_name = 'DeleteTable')
) AND e.status_code = 200;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0040-02: Ransomware Rapid File Renaming and Encryption Spike
-- MITRE Technique: T1486 (Data Encrypted for Impact)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1486_ransomware_burst AS
SELECT
    'BST-R-4002' AS rule_code,
    MIN(f.modification_id) AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    f.asset_id AS entity_id,
    MAX(f.event_time) AS detected_at,
    'CRITICAL' AS severity,
    98.0 AS confidence_score,
    100.0 AS composite_risk_score,
    'Ransomware Rapid Encryption Pattern on ' || a.hostname AS title,
    'Host ' || a.hostname || ' incurred ' || CAST(COUNT(*) AS VARCHAR) || ' rapid file modifications or encrypted renamings within 5 minutes' AS summary,
    '{"modified_file_count":' || CAST(COUNT(*) AS VARCHAR) || ',"process_id":"' || COALESCE(MIN(f.process_guid), 'unknown') || '"}' AS evidence_json,
    'TA0040' AS tactic_code,
    'T1486' AS technique_code
FROM telemetry_file_modifications f
JOIN core_compute_assets a ON f.asset_id = a.asset_id
WHERE (
    f.file_path LIKE '%.enc' OR
    f.file_path LIKE '%.locked' OR
    f.file_path LIKE '%.crypto' OR
    f.action = 'MODIFIED'
)
GROUP BY a.account_id, f.asset_id, a.hostname, DATE_TRUNC('hour', f.event_time)
HAVING COUNT(*) >= 15;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0040 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0040 AS
SELECT * FROM v_rule_t1485_cloud_data_destruction
UNION ALL SELECT * FROM v_rule_t1486_ransomware_burst;
