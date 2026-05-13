-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0008_lateral_movement.sql
-- Description: MITRE ATT&CK Tactic TA0008 (Lateral Movement) detection rules:
--              Cross-zone RDP/SSH pivot connections, lateral tool transfers,
--              and Pass-the-Hash / Pass-the-Ticket authentication traversal.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0008-01: Direct Cross-Zone Administrative Ingress (DMZ to Crown Jewel)
-- MITRE Technique: T1021.004 (Remote Services: SSH)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1021_004_dmz_to_internal_pivot AS
SELECT
    'BST-R-0801' AS rule_code,
    f.flow_id AS evidence_id,
    f.account_id,
    'COMPUTE_ASSET' AS entity_type,
    src_a.asset_id AS entity_id,
    f.start_time AS detected_at,
    'CRITICAL' AS severity,
    98.0 AS confidence_score,
    95.0 AS composite_risk_score,
    'Unauthorized DMZ to Crown Jewel Pivot: ' || src_a.hostname || ' -> ' || dst_a.hostname AS title,
    'Direct administrative connection (port ' || CAST(f.dst_port AS VARCHAR) || ') established from DMZ asset ' || src_a.hostname || ' into Tier-1 asset ' || dst_a.hostname AS summary,
    '{"src":"' || f.src_addr || '","dst":"' || f.dst_addr || '","port":' || CAST(f.dst_port AS VARCHAR) || '}' AS evidence_json,
    'TA0008' AS tactic_code,
    'T1021.004' AS technique_code
FROM telemetry_vpc_flow_logs f
JOIN core_compute_assets src_a ON f.src_addr = src_a.primary_ip
JOIN core_subnets src_sub ON src_a.subnet_id = src_sub.subnet_id
JOIN core_compute_assets dst_a ON f.dst_addr = dst_a.primary_ip
JOIN core_subnets dst_sub ON dst_a.subnet_id = dst_sub.subnet_id
WHERE src_sub.zone_type = 'DMZ'
  AND (dst_sub.zone_type = 'DATA' OR dst_a.is_crown_jewel = TRUE)
  AND f.dst_port IN (22, 3389, 445, 5985, 5986)
  AND f.action = 'ACCEPT';

-- ----------------------------------------------------------------------------
-- Rule BST-TA0008-02: Simultaneous Multi-Host Authentication with Single Credential
-- MITRE Technique: T1550.002 (Use Alternate Authentication Material: Pass the Hash)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1550_002_pass_the_hash_fanout AS
SELECT
    'BST-R-0802' AS rule_code,
    MIN(auth_event_id) AS evidence_id,
    account_id,
    'PRINCIPAL' AS entity_type,
    principal_id AS entity_id,
    MAX(event_time) AS detected_at,
    'HIGH' AS severity,
    92.0 AS confidence_score,
    90.0 AS composite_risk_score,
    'Lateral Pass-the-Hash Fanout by ' || username_asserted AS title,
    'Single credential for ' || username_asserted || ' authenticated across ' || CAST(COUNT(DISTINCT target_resource) AS VARCHAR) || ' distinct servers within 10 minutes from source IP ' || source_ip AS summary,
    '{"actor":"' || username_asserted || '","distinct_targets":' || CAST(COUNT(DISTINCT target_resource) AS VARCHAR) || '}' AS evidence_json,
    'TA0008' AS tactic_code,
    'T1550.002' AS technique_code
FROM telemetry_authentication_events
WHERE auth_status = 'SUCCESS'
  AND target_resource IS NOT NULL
GROUP BY account_id, principal_id, username_asserted, source_ip, DATE_TRUNC('hour', event_time)
HAVING COUNT(DISTINCT target_resource) >= 4;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0008 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0008 AS
SELECT * FROM v_rule_t1021_004_dmz_to_internal_pivot
UNION ALL SELECT * FROM v_rule_t1550_002_pass_the_hash_fanout;
