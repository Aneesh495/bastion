-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/07_incident.sql
-- Description: Deterministic Finite Automaton (DFA) incident lifecycle, multi-signal
--              alert correlation, containment directives, and automated remediation.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. DFA State Transition Invariants
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_dfa_transitions (
    transition_id       VARCHAR(64) PRIMARY KEY,
    from_state          VARCHAR(32) NOT NULL,
    to_state            VARCHAR(32) NOT NULL,
    is_allowed          BOOLEAN NOT NULL DEFAULT TRUE,
    required_clearance  VARCHAR(32) NOT NULL DEFAULT 'STANDARD',
    guard_description   TEXT NOT NULL,
    CONSTRAINT uq_dfa_pair UNIQUE (from_state, to_state)
);

-- Seed baseline deterministic finite automaton transition matrix
INSERT INTO incident_dfa_transitions (transition_id, from_state, to_state, is_allowed, required_clearance, guard_description) VALUES
('tr-01', 'DETECTED',        'TRIAGED',        TRUE,  'STANDARD',     'Initial analyst assignment or automated priority queueing'),
('tr-02', 'DETECTED',        'FALSE_POSITIVE', TRUE,  'STANDARD',     'Immediate dismissal upon benign activity validation'),
('tr-03', 'TRIAGED',         'CONTAINED',      TRUE,  'CONFIDENTIAL', 'Execution of containment directive (host isolation or credential revocation)'),
('tr-04', 'TRIAGED',         'FALSE_POSITIVE', TRUE,  'CONFIDENTIAL', 'Dismissal following detailed investigation'),
('tr-05', 'CONTAINED',       'REMEDIATED',     TRUE,  'SECRET',       'Neutralization of persistence mechanisms and IOC purging'),
('tr-06', 'REMEDIATED',      'RESOLVED',       TRUE,  'SECRET',       'Verification of zero recurrence and audit closure'),
('tr-07', 'CONTAINED',       'TRIAGED',        TRUE,  'SECRET',       'Rollback of containment upon false-alarm finding'),
('tr-08', 'RESOLVED',        'DETECTED',       TRUE,  'TOP_SECRET',   'Reopening incident upon subsequent related signal recurrence');

-- ----------------------------------------------------------------------------
-- 2. Core Security Incidents
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incidents (
    incident_id         VARCHAR(64) PRIMARY KEY,
    title               VARCHAR(255) NOT NULL,
    severity            VARCHAR(16) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    current_state       VARCHAR(32) NOT NULL DEFAULT 'DETECTED' CHECK (current_state IN (
                            'DETECTED', 'TRIAGED', 'CONTAINED', 'REMEDIATED', 'RESOLVED', 'FALSE_POSITIVE'
                        )),
    composite_risk_score NUMERIC(5,2) NOT NULL CHECK (composite_risk_score BETWEEN 0.0 AND 100.0),
    blast_radius_assets INTEGER NOT NULL DEFAULT 1 CHECK (blast_radius_assets >= 0),
    primary_tactic_code VARCHAR(16) NOT NULL,
    root_cause_summary  TEXT,
    assigned_analyst_id VARCHAR(64) REFERENCES core_identity_principals(principal_id),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at           TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 3. Incident to Alert Relational Graph Mapping
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_alert_links (
    link_id             VARCHAR(64) PRIMARY KEY,
    incident_id         VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    alert_id            VARCHAR(64) NOT NULL REFERENCES detection_alerts(alert_id),
    kill_chain_order    INTEGER NOT NULL DEFAULT 1,
    correlation_weight  NUMERIC(5,2) NOT NULL DEFAULT 1.00,
    linked_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_incident_alert UNIQUE (incident_id, alert_id)
);

-- ----------------------------------------------------------------------------
-- 4. Incident State Audit Log (DFA Trajectory History)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_state_history (
    history_id          VARCHAR(64) PRIMARY KEY,
    incident_id         VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    from_state          VARCHAR(32) NOT NULL,
    to_state            VARCHAR(32) NOT NULL,
    actor_principal_id  VARCHAR(64) REFERENCES core_identity_principals(principal_id),
    transition_reason   TEXT NOT NULL,
    transitioned_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 5. Automated Containment and Remediation Directives
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS incident_remediation_actions (
    action_id           VARCHAR(64) PRIMARY KEY,
    incident_id         VARCHAR(64) NOT NULL REFERENCES incidents(incident_id),
    action_type         VARCHAR(32) NOT NULL CHECK (action_type IN (
                            'REVOKE_IAM_SESSION', 'DETACH_OVERPRIVILEGED_POLICY',
                            'QUARANTINE_COMPUTE_HOST', 'BLOCK_FIREWALL_CIDR',
                            'DISABLE_CREDENTIAL', 'ENFORCE_STEP_UP_MFA', 'SNAPSHOT_DISK_FORENSICS'
                        )),
    target_entity_type  VARCHAR(32) NOT NULL,
    target_entity_id    VARCHAR(64) NOT NULL,
    synthesized_sql_cmd TEXT NOT NULL,
    execution_status    VARCHAR(16) NOT NULL DEFAULT 'PENDING' CHECK (execution_status IN ('PENDING', 'EXECUTED', 'FAILED', 'ROLLED_BACK')),
    executed_at         TIMESTAMP,
    execution_output    TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_incident_state ON incidents(current_state, severity);
CREATE INDEX IF NOT EXISTS idx_inc_history ON incident_state_history(incident_id, transitioned_at);
CREATE INDEX IF NOT EXISTS idx_remediation_inc ON incident_remediation_actions(incident_id, execution_status);
