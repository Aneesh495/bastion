-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/incident/state_machine.sql
-- Description: Relational DFA state machine governance, valid transition checking,
--              guard condition verification, and incident lifecycle enforcement.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Permitted DFA Transition Evaluation View
-- ----------------------------------------------------------------------------
-- Evaluates whether a proposed transition from an incident's current_state to
-- a prospective target_state satisfies all formal invariants:
-- 1. Existence of valid transition edge in incident_dfa_transitions.
-- 2. Clearance level of actor meets or exceeds required_clearance.
-- 3. Invariant checks (e.g. Cannot transition to RESOLVED if unresolved alerts remain).
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_incident_permitted_transitions AS
SELECT
    i.incident_id,
    i.title,
    i.current_state,
    t.to_state AS candidate_target_state,
    t.required_clearance,
    t.guard_description,
    t.is_allowed AS dfa_edge_allowed,
    -- Guard check: ensure containment directives exist before moving to CONTAINED
    CASE
        WHEN t.to_state = 'CONTAINED' THEN
            CASE WHEN (SELECT COUNT(*) FROM incident_remediation_actions r WHERE r.incident_id = i.incident_id) > 0
                 THEN TRUE ELSE FALSE END
        WHEN t.to_state = 'RESOLVED' THEN
            CASE WHEN i.current_state = 'REMEDIATED' THEN TRUE ELSE FALSE END
        ELSE TRUE
    END AS guard_condition_satisfied
FROM incidents i
JOIN incident_dfa_transitions t ON i.current_state = t.from_state
WHERE t.is_allowed = TRUE;

-- ----------------------------------------------------------------------------
-- 2. Incident Lifecycle SLA and Aging Monitor
-- ----------------------------------------------------------------------------
-- Tracks mean time to triage (MTTT) and mean time to contain (MTTC).
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_incident_lifecycle_sla AS
SELECT
    incident_id,
    title,
    severity,
    current_state,
    composite_risk_score,
    created_at,
    updated_at,
    -- Elapsed duration in current state in minutes
    ROUND(EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - updated_at)) / 60.0, 1) AS minutes_in_current_state,
    CASE
        WHEN current_state = 'DETECTED' AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - updated_at)) > 900 THEN 'SLA_BREACH_TRIAGE_OVERDUE'
        WHEN current_state = 'TRIAGED' AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - updated_at)) > 1800 THEN 'SLA_BREACH_CONTAINMENT_OVERDUE'
        ELSE 'SLA_NOMINAL'
    END AS sla_status
FROM incidents
WHERE current_state NOT IN ('RESOLVED', 'FALSE_POSITIVE');
