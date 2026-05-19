-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0010_exfiltration.sql
-- Description: MITRE ATT&CK Tactic TA0010 (Exfiltration) detection rules:
--              DNS exfiltration tunneling, cloud storage synchronization,
--              and massive single-destination outbound data transfers.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0010-01: DNS Query Length and Volume Tunneling (Exfiltration Channel)
-- MITRE Technique: T1048.003 (Exfiltration Over Alternative Protocol: DNS Tunneling)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1048_003_dns_tunneling AS
SELECT
    'BST-R-1001' AS rule_code,
    MIN(q.query_id) AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    q.asset_id AS entity_id,
    MAX(q.query_time) AS detected_at,
    'CRITICAL' AS severity,
    96.0 AS confidence_score,
    95.0 AS composite_risk_score,
    'DNS Data Exfiltration Tunneling on ' || a.hostname AS title,
    'Host ' || a.hostname || ' generated ' || CAST(COUNT(*) AS VARCHAR) || ' high-length DNS queries with mean query length ' || CAST(ROUND(AVG(LENGTH(q.query_name)), 1) AS VARCHAR) || ' chars' AS summary,
    '{"dns_query_count":' || CAST(COUNT(*) AS VARCHAR) || ',"avg_length":' || CAST(ROUND(AVG(LENGTH(q.query_name)), 1) AS VARCHAR) || ',"entropy":' || CAST(ROUND(AVG(q.entropy_score), 2) AS VARCHAR) || '}' AS evidence_json,
    'TA0010' AS tactic_code,
    'T1048.003' AS technique_code
FROM telemetry_dns_queries q
JOIN core_compute_assets a ON q.asset_id = a.asset_id
WHERE LENGTH(q.query_name) >= 45
GROUP BY a.account_id, q.asset_id, a.hostname, DATE_TRUNC('hour', q.query_time)
HAVING COUNT(*) >= 15;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0010-02: Exfiltration to External Unmanaged Cloud Bucket
-- MITRE Technique: T1567.002 (Exfiltration to Cloud Storage)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1567_002_external_bucket_sync AS
SELECT
    'BST-R-1002' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'HIGH' AS severity,
    92.0 AS confidence_score,
    90.0 AS composite_risk_score,
    'External Cloud Storage Sync Tool on ' || a.hostname AS title,
    'Process ' || p.process_name || ' invoked cloud sync utility targeting external endpoints: ' || SUBSTR(p.command_line, 1, 150) AS summary,
    '{"cmd":"' || SUBSTR(p.command_line, 1, 200) || '","user":"' || p.executing_user || '"}' AS evidence_json,
    'TA0010' AS tactic_code,
    'T1567.002' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    p.command_line LIKE '%rclone sync%' OR
    p.command_line LIKE '%rclone copy%' OR
    p.command_line LIKE '%aws s3 sync %s3://%' OR
    p.command_line LIKE '%gsutil cp -r %' OR
    p.command_line LIKE '%mega-cmd%'
);

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0010 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0010 AS
SELECT * FROM v_rule_t1048_003_dns_tunneling
UNION ALL SELECT * FROM v_rule_t1567_002_external_bucket_sync;
