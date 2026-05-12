-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0007_discovery.sql
-- Description: MITRE ATT&CK Tactic TA0007 (Discovery) detection rules:
--              Internal network port sweeps, cloud service enumeration,
--              account discovery, and system reconnaissance commands.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0007-01: Rapid Internal Network Port Sweep (Subnet Scanning)
-- MITRE Technique: T1046 (Network Service Discovery)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1046_internal_port_scan AS
SELECT
    'BST-R-0701' AS rule_code,
    MIN(f.flow_id) AS evidence_id,
    f.account_id,
    'COMPUTE_ASSET' AS entity_type,
    a.asset_id AS entity_id,
    MAX(f.start_time) AS detected_at,
    'HIGH' AS severity,
    94.0 AS confidence_score,
    88.0 AS composite_risk_score,
    'Horizontal Port Scan by ' || a.hostname AS title,
    'Host ' || a.hostname || ' (' || f.src_addr || ') scanned ' || CAST(COUNT(DISTINCT f.dst_addr) AS VARCHAR) || ' distinct internal IPs across ' || CAST(COUNT(DISTINCT f.dst_port) AS VARCHAR) || ' ports within 10 minutes' AS summary,
    '{"src":"' || f.src_addr || '","targets_scanned":' || CAST(COUNT(DISTINCT f.dst_addr) AS VARCHAR) || ',"ports":' || CAST(COUNT(DISTINCT f.dst_port) AS VARCHAR) || '}' AS evidence_json,
    'TA0007' AS tactic_code,
    'T1046' AS technique_code
FROM telemetry_vpc_flow_logs f
JOIN core_compute_assets a ON f.src_addr = a.primary_ip
GROUP BY f.account_id, a.asset_id, a.hostname, f.src_addr, DATE_TRUNC('hour', f.start_time)
HAVING COUNT(DISTINCT f.dst_addr) >= 10 OR COUNT(DISTINCT f.dst_port) >= 20;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0007-02: Broad Cloud Service and IAM Permissions Enumeration
-- MITRE Technique: T1087.004 (Account Discovery: Cloud Account)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1087_004_cloud_enumeration AS
SELECT
    'BST-R-0702' AS rule_code,
    MIN(e.event_id) AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    MAX(e.event_time) AS detected_at,
    'HIGH' AS severity,
    88.0 AS confidence_score,
    84.0 AS composite_risk_score,
    'Automated Cloud Discovery Enumeration by ' || e.principal_arn AS title,
    'Identity ' || e.principal_arn || ' executed ' || CAST(COUNT(*) AS VARCHAR) || ' read-only reconnaissance API calls across ' || CAST(COUNT(DISTINCT e.event_name) AS VARCHAR) || ' distinct APIs' AS summary,
    '{"actor":"' || e.principal_arn || '","recon_api_count":' || CAST(COUNT(DISTINCT e.event_name) AS VARCHAR) || '}' AS evidence_json,
    'TA0007' AS tactic_code,
    'T1087.004' AS technique_code
FROM telemetry_cloudtrail_events e
WHERE e.event_name IN (
    'GetAccountAuthorizationDetails', 'ListUsers', 'ListRoles',
    'ListPolicies', 'DescribeInstances', 'DescribeSecurityGroups',
    'DescribeDBInstances', 'ListBuckets'
) AND e.status_code = 200
GROUP BY e.account_id, e.principal_id, e.principal_arn, DATE_TRUNC('hour', e.event_time)
HAVING COUNT(DISTINCT e.event_name) >= 4;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0007 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0007 AS
SELECT * FROM v_rule_t1046_internal_port_scan
UNION ALL SELECT * FROM v_rule_t1087_004_cloud_enumeration;
