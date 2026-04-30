-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0001_initial_access.sql
-- Description: MITRE ATT&CK Tactic TA0001 (Initial Access) detection rules:
--              Valid accounts, console access without MFA, Tor ingress, dormant
--              account re-activation, and public-facing application exploits.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0001-01: Cloud Console Login Without Multi-Factor Authentication
-- MITRE Technique: T1078.004 (Valid Accounts: Cloud Accounts)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1078_004_console_login_no_mfa AS
SELECT
    'BST-R-0101' AS rule_code,
    e.event_id AS evidence_id,
    e.account_id,
    'PRINCIPAL' AS entity_type,
    e.principal_id AS entity_id,
    e.event_time AS detected_at,
    'CRITICAL' AS severity,
    95.0 AS confidence_score,
    92.0 AS composite_risk_score,
    'Console Login Without Multi-Factor Authentication: ' || p.username AS title,
    'Identity ' || p.username || ' performed administrative console sign-in without MFA enforcement from source IP ' || e.source_ip_address AS summary,
    '{"event_name":"' || e.event_name || '","source_ip":"' || e.source_ip_address || '","user_agent":"' || COALESCE(e.user_agent, 'unknown') || '"}' AS evidence_json,
    'TA0001' AS tactic_code,
    'T1078.004' AS technique_code
FROM telemetry_cloudtrail_events e
JOIN core_identity_principals p ON e.principal_id = p.principal_id
WHERE e.event_name = 'ConsoleLogin'
  AND (e.request_parameters NOT LIKE '%"MFAUsed": "Yes"%' OR e.request_parameters IS NULL)
  AND e.status_code = 200;

-- ----------------------------------------------------------------------------
-- Rule BST-TA0001-02: Remote Access Attempt from Known Tor Exit Node or Proxy
-- MITRE Technique: T1133 (External Remote Services)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1133_tor_remote_access AS
SELECT
    'BST-R-0102' AS rule_code,
    a.auth_event_id AS evidence_id,
    a.account_id,
    'PRINCIPAL' AS entity_type,
    a.principal_id AS entity_id,
    a.event_time AS detected_at,
    'CRITICAL' AS severity,
    98.0 AS confidence_score,
    96.0 AS composite_risk_score,
    'Authentication Ingress from Known Tor Exit Node: ' || a.username_asserted AS title,
    'Principal ' || a.username_asserted || ' authenticated from verified Tor exit node ' || a.source_ip AS summary,
    '{"source_ip":"' || a.source_ip || '","threat_category":"' || i.threat_category || '","feed":"' || i.source_feed || '"}' AS evidence_json,
    'TA0001' AS tactic_code,
    'T1133' AS technique_code
FROM telemetry_authentication_events a
JOIN intel_indicators_ip i ON a.source_ip = i.ip_address
WHERE i.threat_category IN ('TOR_EXIT_NODE', 'ANONYMIZING_PROXY')
  AND i.is_active = TRUE
  AND a.auth_status = 'SUCCESS';

-- ----------------------------------------------------------------------------
-- Rule BST-TA0001-03: Dormant Identity Account Re-activation and Sudden Burst
-- MITRE Technique: T1078.003 (Valid Accounts: Local Accounts)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1078_003_dormant_account_reactivation AS
SELECT
    'BST-R-0103' AS rule_code,
    a.auth_event_id AS evidence_id,
    p.account_id,
    'PRINCIPAL' AS entity_type,
    p.principal_id AS entity_id,
    a.event_time AS detected_at,
    'HIGH' AS severity,
    88.0 AS confidence_score,
    85.0 AS composite_risk_score,
    'Dormant Account Re-activation: ' || p.username AS title,
    'Account ' || p.username || ' authenticated after exceeding 90 days of inactivity' AS summary,
    '{"last_login":"' || CAST(p.last_login_at AS VARCHAR) || '","event_time":"' || CAST(a.event_time AS VARCHAR) || '"}' AS evidence_json,
    'TA0001' AS tactic_code,
    'T1078.003' AS technique_code
FROM telemetry_authentication_events a
JOIN core_identity_principals p ON a.principal_id = p.principal_id
WHERE a.auth_status = 'SUCCESS'
  AND p.last_login_at IS NOT NULL
  AND EXTRACT(EPOCH FROM (a.event_time - p.last_login_at)) > (90 * 86400);

-- ----------------------------------------------------------------------------
-- Rule BST-TA0001-04: Web Ingress Application Exploit (SQLi or Path Traversal)
-- MITRE Technique: T1190 (Exploit Public-Facing Application)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1190_web_application_exploit AS
SELECT
    'BST-R-0104' AS rule_code,
    h.request_id AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    h.asset_id AS entity_id,
    h.request_time AS detected_at,
    'HIGH' AS severity,
    90.0 AS confidence_score,
    88.0 AS composite_risk_score,
    'Web Ingress Application Attack Pattern on ' || a.hostname AS title,
    'HTTP request to ' || h.uri_path || ' contained signature path traversal or SQL injection patterns' AS summary,
    '{"client_ip":"' || h.client_ip || '","uri":"' || h.uri_path || '","status":' || CAST(h.status_code AS VARCHAR) || '}' AS evidence_json,
    'TA0001' AS tactic_code,
    'T1190' AS technique_code
FROM telemetry_http_access_logs h
JOIN core_compute_assets a ON h.asset_id = a.asset_id
WHERE (h.uri_path LIKE '%..%' OR h.uri_path LIKE '%/etc/passwd%' OR h.uri_path LIKE '%union%select%' OR h.query_string LIKE '%union%select%')
  AND h.status_code IN (200, 500);

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0001 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0001 AS
SELECT * FROM v_rule_t1078_004_console_login_no_mfa
UNION ALL SELECT * FROM v_rule_t1133_tor_remote_access
UNION ALL SELECT * FROM v_rule_t1078_003_dormant_account_reactivation
UNION ALL SELECT * FROM v_rule_t1190_web_application_exploit;
