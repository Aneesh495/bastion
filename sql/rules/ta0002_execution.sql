-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta0002_execution.sql
-- Description: MITRE ATT&CK Tactic TA0002 (Execution) detection rules:
--              Base64 encoded PowerShell, interactive reverse shells, spawned
--              interactive subshells, and scheduled task executions.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Rule BST-TA0002-01: Suspicious Encoded PowerShell Command Execution
-- MITRE Technique: T1059.001 (Command and Scripting Interpreter: PowerShell)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1059_001_powershell_encoded_command AS
SELECT
    'BST-R-0201' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'CRITICAL' AS severity,
    96.0 AS confidence_score,
    94.0 AS composite_risk_score,
    'Obfuscated PowerShell Execution on ' || a.hostname AS title,
    'Process ' || p.process_name || ' (PID ' || CAST(p.pid AS VARCHAR) || ') executed with base64 encoded or execution-bypass arguments' AS summary,
    '{"process":"' || p.process_name || '","cmd":"' || SUBSTR(p.command_line, 1, 200) || '","hash":"' || p.hash_sha256 || '"}' AS evidence_json,
    'TA0002' AS tactic_code,
    'T1059.001' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE LOWER(p.process_name) LIKE '%powershell%'
  AND (
      LOWER(p.command_line) LIKE '%-enc%' OR
      LOWER(p.command_line) LIKE '%-encodedcommand%' OR
      LOWER(p.command_line) LIKE '%-nop%' OR
      LOWER(p.command_line) LIKE '%bypass%'
  );

-- ----------------------------------------------------------------------------
-- Rule BST-TA0002-02: Unix Reverse Interactive Shell Pipeline Execution
-- MITRE Technique: T1059.004 (Command and Scripting Interpreter: Unix Shell)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1059_004_unix_reverse_shell AS
SELECT
    'BST-R-0202' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'CRITICAL' AS severity,
    98.0 AS confidence_score,
    98.0 AS composite_risk_score,
    'Interactive Reverse Shell Command on ' || a.hostname AS title,
    'Process ' || p.process_name || ' invoked an interactive shell bound to standard network streams: ' || SUBSTR(p.command_line, 1, 100) AS summary,
    '{"process":"' || p.process_name || '","command_line":"' || SUBSTR(p.command_line, 1, 250) || '","user":"' || p.executing_user || '"}' AS evidence_json,
    'TA0002' AS tactic_code,
    'T1059.004' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    p.command_line LIKE '%/dev/tcp/%' OR
    p.command_line LIKE '%nc -e %' OR
    p.command_line LIKE '%ncat -e %' OR
    p.command_line LIKE '%pty.spawn%' OR
    p.command_line LIKE '%curl | bash%' OR
    p.command_line LIKE '%wget -O - | sh%'
);

-- ----------------------------------------------------------------------------
-- Rule BST-TA0002-03: Scheduled Task or Cron Execution with Elevated Privileges
-- MITRE Technique: T1053.005 (Scheduled Task/Job: Scheduled Task)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_rule_t1053_005_scheduled_task_spawn AS
SELECT
    'BST-R-0203' AS rule_code,
    p.process_guid AS evidence_id,
    a.account_id,
    'COMPUTE_ASSET' AS entity_type,
    p.asset_id AS entity_id,
    p.event_time AS detected_at,
    'HIGH' AS severity,
    88.0 AS confidence_score,
    85.0 AS composite_risk_score,
    'Suspicious Task Scheduler Invocation on ' || a.hostname AS title,
    'Elevated process ' || p.process_name || ' manipulated system scheduled tasks: ' || SUBSTR(p.command_line, 1, 120) AS summary,
    '{"cmd":"' || SUBSTR(p.command_line, 1, 200) || '","integrity":"' || COALESCE(p.integrity_level, 'SYSTEM') || '"}' AS evidence_json,
    'TA0002' AS tactic_code,
    'T1053.005' AS technique_code
FROM telemetry_process_events p
JOIN core_compute_assets a ON p.asset_id = a.asset_id
WHERE (
    LOWER(p.process_name) IN ('schtasks.exe', 'at.exe', 'crontab') OR
    p.command_line LIKE '%schtasks /create%' OR
    p.command_line LIKE '%crontab -e%'
) AND p.is_elevated = TRUE;

-- ----------------------------------------------------------------------------
-- Consolidated View for Tactic TA0002 Findings
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_findings_ta0002 AS
SELECT * FROM v_rule_t1059_001_powershell_encoded_command
UNION ALL SELECT * FROM v_rule_t1059_004_unix_reverse_shell
UNION ALL SELECT * FROM v_rule_t1053_005_scheduled_task_spawn;
