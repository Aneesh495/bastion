-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/incident/playbook_synthesis.sql
-- Description: Automated containment directive generation and executable SQL
--              remediation command synthesis for rapid incident response.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Dynamic Remediation Command Synthesizer
-- ----------------------------------------------------------------------------
-- Automatically generates idempotent SQL remediation statements based on the
-- entity type, attack severity, and observed MITRE tactics of an active incident.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_synthesized_containment_playbook AS
-- Directive 1: Host Network Isolation for Compromised Compute Assets
SELECT
    i.incident_id,
    'QUARANTINE_COMPUTE_HOST' AS action_type,
    a.entity_type AS target_entity_type,
    a.entity_id AS target_entity_id,
    'ISOLATE_HOST: ' || a.entity_id AS action_summary,
    'UPDATE core_compute_assets SET is_quarantined = TRUE, state = ''ISOLATED'' WHERE asset_id = ''' || a.entity_id || ''';' AS synthesized_sql_cmd,
    1 AS execution_priority
FROM incidents i
JOIN incident_alert_links l ON i.incident_id = l.incident_id
JOIN detection_alerts a ON l.alert_id = a.alert_id
WHERE a.entity_type = 'COMPUTE_ASSET'
  AND i.current_state IN ('DETECTED', 'TRIAGED')

UNION ALL

-- Directive 2: Credential Revocation for Compromised Identities
SELECT
    i.incident_id,
    'REVOKE_IAM_SESSION' AS action_type,
    a.entity_type AS target_entity_type,
    a.entity_id AS target_entity_id,
    'REVOKE_CREDENTIALS: ' || a.entity_id AS action_summary,
    'UPDATE core_identity_principals SET is_active = FALSE WHERE principal_id = ''' || a.entity_id || '''; UPDATE core_credentials SET is_active = FALSE, is_compromised = TRUE WHERE principal_id = ''' || a.entity_id || ''';' AS synthesized_sql_cmd,
    1 AS execution_priority
FROM incidents i
JOIN incident_alert_links l ON i.incident_id = l.incident_id
JOIN detection_alerts a ON l.alert_id = a.alert_id
WHERE a.entity_type = 'PRINCIPAL'
  AND i.current_state IN ('DETECTED', 'TRIAGED')

UNION ALL

-- Directive 3: Policy Detachment for Overprivileged Escalation
SELECT
    i.incident_id,
    'DETACH_OVERPRIVILEGED_POLICY' AS action_type,
    a.entity_type AS target_entity_type,
    a.entity_id AS target_entity_id,
    'DETACH_ADMIN_POLICIES: ' || a.entity_id AS action_summary,
    'DELETE FROM core_iam_policy_attachments WHERE principal_id = ''' || a.entity_id || ''' AND policy_id IN (SELECT policy_id FROM core_iam_policies WHERE is_overprivileged = TRUE);' AS synthesized_sql_cmd,
    2 AS execution_priority
FROM incidents i
JOIN incident_alert_links l ON i.incident_id = l.incident_id
JOIN detection_alerts a ON l.alert_id = a.alert_id
WHERE a.technique_code IN ('T1078.004', 'T1098.001')
  AND i.current_state IN ('DETECTED', 'TRIAGED');
