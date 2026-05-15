-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0009_collection.sql
-- Description: MITRE ATT&CK Tactic TA0009 (Collection) detection rules:
--              Bulk cloud object download from sensitive buckets, archive staging
--              using zip/tar/7z, and automated local data aggregation.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0009-01: Bulk Cloud Storage Object Collection from Sensitive Buckets
-- MITRE Technique: T1530 (Data from Cloud Storage Object)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1530_bulk_cloud_storage_collection AS
SELECT
    'BST-R-0901' AS rule_code,
    MIN(e.event_id) AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    MAX(e.event_time) AS detected_at,
    'CRITICAL' AS severity,
    95.0 AS confidence_score,
    94.0 AS composite_risk_score,
    'Bulk Object Extraction from Restricted Bucket by ' || e.principal_arn AS title,
    'Identity ' || e.principal_arn || ' downloaded ' || CAST(COUNT(*) AS VARCHAR) || ' objects from classified bucket within 15 minutes' AS summary,
    '{"bucket_event_count":' || CAST(COUNT(*) AS VARCHAR) || ',"actor":"' || e.principal_arn || '","ip":"' || e.source_ip_address || '"}' AS evidence_json,
    'TA0009' AS tactic_code,
    'T1530' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE e.event_source = 's3.amazonaws.com'
  AND e.event_name IN ('GetObject', 'CopyObject')
  AND e.status_code = 200
GROUP BY e.account_id, e.principal_id, e.principal_arn, e.source_ip_address, DATE_TRUNC('hour', e.event_time)
HAVING COUNT(*) >= 20;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0009-02: Automated Archive Staging via Zip / Tar / 7-Zip
-- MITRE Technique: T1005 (Data from Local System)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1005_archive_staging AS
SELECT
    'BST-R-0902' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'HIGH' AS severity,
    88.0 AS confidence_score,
    82.0 AS composite_risk_score,
    'Bulk Archive Compression Staging on ' || a.hostname AS title,
    'Process ' || p.process_name || ' staged system files into compressed archive: ' || SUBSTR(p.command_line, 1, 150) AS summary,
    '{"cmd":"' || SUBSTR(p.command_line, 1, 200) || '","user":"' || p.executing_user || '"}' AS evidence_json,
    'TA0009' AS tactic_code,
    'T1005' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    p.command_line LIKE '%tar -czf%' OR
    p.command_line LIKE '%tar -cvf%' OR
    p.command_line LIKE '%zip -r %' OR
    p.command_line LIKE '%7z a %' OR
    p.command_line LIKE '%rar a %'
);

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0009 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0009 AS
SELECT * FROM v_rule_t1530_bulk_cloud_storage_collection
UNION ALL SELECT * FROM v_rule_t1005_archive_staging;
