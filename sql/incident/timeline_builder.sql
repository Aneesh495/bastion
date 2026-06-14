-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/incident/timeline_builder.sql
-- Description: Chronological attack timeline reconstruction, causal event DAG
--              synthesis, adversary dwell-time calculation, and narrative rollups.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Unified Event Timeline Reconstruction
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_incident_chronological_timelines AS
WITH incident_alerts_unrolled AS (
    SELECT
        l.incident_id,
        l.kill_chain_order,
        a.alert_id,
        a.rule_id,
        a.entity_type,
        a.entity_id,
        a.tactic_code,
        a.technique_code,
        a.severity,
        a.composite_risk_score,
        a.title,
        a.summary,
        a.detected_at,
        t.display_order AS tactic_order
    FROM incident_alert_links l
    JOIN detection_alerts a ON l.alert_id = a.alert_id
    JOIN intel_mitre_tactics t ON a.tactic_code = t.tactic_code
)
SELECT
    incident_id,
    ROW_NUMBER() OVER (PARTITION BY incident_id ORDER BY detected_at, tactic_order) AS step_number,
    detected_at AS event_timestamp,
    tactic_code,
    technique_code,
    severity,
    entity_type,
    entity_id,
    title,
    summary,
    composite_risk_score,
    -- Elapsed time since initial observed intrusion event in minutes
    ROUND(EXTRACT(EPOCH FROM (detected_at - MIN(detected_at) OVER (PARTITION BY incident_id))) / 60.0, 1) AS minutes_since_initial_ingress
FROM incident_alerts_unrolled;

-- ----------------------------------------------------------------------------
-- 2. Incident Adversary Dwell-Time Metric View
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_incident_dwell_time_summary AS
SELECT
    incident_id,
    MIN(event_timestamp) AS initial_compromise_time,
    MAX(event_timestamp) AS latest_activity_time,
    COUNT(*) AS total_milestone_events,
    COUNT(DISTINCT tactic_code) AS tactics_spanned,
    -- Total adversary dwell time in hours
    ROUND(EXTRACT(EPOCH FROM (MAX(event_timestamp) - MIN(event_timestamp))) / 3600.0, 2) AS total_dwell_time_hours,
    CASE
        WHEN EXTRACT(EPOCH FROM (MAX(event_timestamp) - MIN(event_timestamp))) < 3600 THEN 'RAPID_AUTOMATED_STRIKE'
        WHEN EXTRACT(EPOCH FROM (MAX(event_timestamp) - MIN(event_timestamp))) < 86400 THEN 'MODERATE_INTRA_DAY_CAMPAIGN'
        ELSE 'PERSISTENT_SLOW_BURN_APT'
    END AS campaign_velocity_profile
FROM v_incident_chronological_timelines
GROUP BY incident_id;
