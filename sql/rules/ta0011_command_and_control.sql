-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0011_command_and_control.sql
-- Description: MITRE ATT&CK Tactic TA0011 (Command and Control) detection rules:
--              Direct connection to known threat actor C2 IPs, DGA query execution,
--              and periodic heartbeats to external destinations.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0011-01: Direct Communication with Known C2 Infrastructure IP
-- MITRE Technique: T1071.001 (Application Layer Protocol: Web Protocols)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1071_001_c2_ip_communication AS
SELECT
    'BST-R-1101' AS rule_code,
    f.flow_id AS evidence_id,
    f.account_id,
    'COMPUTE_ASSET' AS entity_type,
    a.asset_id AS entity_id,
    f.start_time AS detected_at,
    'CRITICAL' AS severity,
    100.0 AS confidence_score,
    99.0 AS composite_risk_score,
    'Outbound Communication to Confirmed C2 Server: ' || f.dst_addr AS title,
    'Host ' || a.hostname || ' (' || f.src_addr || ') established connection to confirmed threat intelligence C2 IP ' || f.dst_addr || ' (Feed: ' || i.source_feed || ')' AS summary,
    '{"src":"' || f.src_addr || '","dst":"' || f.dst_addr || '","actor":"' || COALESCE(i.associated_actor_id, 'UNKNOWN') || '","bytes":' || CAST(f.bytes_transferred AS VARCHAR) || '}' AS evidence_json,
    'TA0011' AS tactic_code,
    'T1071.001' AS technique_code
FROM telemetry_vpc_flow_logs f
JOIN core_compute_assets a ON f.src_addr = a.primary_ip
JOIN intel_indicators_ip i ON f.dst_addr = i.ip_address
WHERE i.threat_category = 'COMMAND_AND_CONTROL'
  AND i.is_active = TRUE
  AND f.action = 'ACCEPT';

-- ----------------------------------------------------------------------------
-- Rule BST-TA0011-02: Algorithmic Domain Resolution Burst (DGA Malware Activity)
-- MITRE Technique: T1568.002 (Dynamic Resolution: Domain Generation Algorithms)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1568_002_dga_resolution AS
SELECT
    'BST-R-1102' AS rule_code,
    q.query_id AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    q.asset_id AS entity_id,
    q.query_time AS detected_at,
    'HIGH' AS severity,
    94.0 AS confidence_score,
    92.0 AS composite_risk_score,
    'DGA Domain Query Burst on ' || a.hostname AS title,
    'Host ' || a.hostname || ' queried algorithmically generated domain ' || q.query_name || ' resulting in ' || q.response_code AS summary,
    '{"domain":"' || q.query_name || '","verdict":"' || d.dga_verdict || '","score":' || CAST(d.dga_confidence_score AS VARCHAR) || '}' AS evidence_json,
    'TA0011' AS tactic_code,
    'T1568.002' AS technique_code
FROM telemetry_dns_queries q
JOIN core_compute_assets a ON q.asset_id = a.asset_id
JOIN v_dga_candidate_domains d ON q.query_id = d.query_id
WHERE d.dga_confidence_score >= 80.0;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0011 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0011 AS
SELECT * FROM v_rule_t1071_001_c2_ip_communication
UNION ALL SELECT * FROM v_rule_t1568_002_dga_resolution;
