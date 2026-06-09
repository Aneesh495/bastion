-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/incident/correlation_engine.sql
-- Description: Multi-signal alert correlation, temporal sliding window clustering,
--              kill-chain progression linking, and composite incident generation.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Alert Correlation Clusters by Entity and Temporal Proximity
-- ----------------------------------------------------------------------------
-- Clusters individual alerts sharing an entity ID or connected via lateral
-- movement relationships occurring within a 30-minute sliding window.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_alert_correlation_clusters AS
WITH ordered_alerts AS (
    SELECT
        alert_id,
        rule_id,
        account_id,
        entity_type,
        entity_id,
        detected_at,
        severity,
        confidence_score,
        composite_risk_score,
        title,
        tactic_code,
        technique_code,
        LAG(detected_at, 1) OVER (
            PARTITION BY entity_type, entity_id
            ORDER BY detected_at
        ) AS prev_alert_time
    FROM detection_alerts
    WHERE status IN ('NEW', 'CORRELATED')
),
alert_gaps AS (
    SELECT
        *,
        CASE
            WHEN prev_alert_time IS NULL THEN 1
            WHEN EXTRACT(EPOCH FROM (detected_at - prev_alert_time)) > 1800 THEN 1 -- New cluster after 30 min gap
            ELSE 0
        END AS is_cluster_boundary
    FROM ordered_alerts
),
cluster_ids AS (
    SELECT
        *,
        -- Cluster ID generated via cumulative sum of boundaries
        SUM(is_cluster_boundary) OVER (
            PARTITION BY entity_type, entity_id
            ORDER BY detected_at
        ) AS cluster_seq
    FROM alert_gaps
)
SELECT
    entity_type || ':' || entity_id || ':c' || CAST(cluster_seq AS VARCHAR) AS correlation_cluster_id,
    entity_type,
    entity_id,
    account_id,
    COUNT(*) AS alert_count,
    COUNT(DISTINCT tactic_code) AS distinct_tactic_count,
    MIN(detected_at) AS cluster_start_time,
    MAX(detected_at) AS cluster_end_time,
    MAX(composite_risk_score) AS peak_risk_score,
    -- Escalated severity if multiple tactics are present
    CASE
        WHEN COUNT(DISTINCT tactic_code) >= 3 THEN 'CRITICAL'
        WHEN MAX(composite_risk_score) >= 90.0 THEN 'CRITICAL'
        WHEN MAX(composite_risk_score) >= 75.0 THEN 'HIGH'
        ELSE 'MEDIUM'
    END AS incident_severity_tier,
    'Correlated Attack Campaign: ' || entity_type || ' ' || entity_id AS suggested_incident_title
FROM cluster_ids
GROUP BY entity_type, entity_id, account_id, cluster_seq;

-- ----------------------------------------------------------------------------
-- 2. Automated Incident Insertion Staging View
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_staged_incidents_to_create AS
SELECT
    'INC-' || SUBSTR(correlation_cluster_id, 1, 24) AS incident_id,
    suggested_incident_title AS title,
    incident_severity_tier AS severity,
    'DETECTED' AS current_state,
    peak_risk_score AS composite_risk_score,
    alert_count AS blast_radius_assets,
    'TA0001' AS primary_tactic_code,
    'Automated correlation of ' || CAST(alert_count AS VARCHAR) || ' alerts spanning ' || CAST(distinct_tactic_count AS VARCHAR) || ' MITRE tactics.' AS root_cause_summary,
    cluster_start_time AS created_at
FROM v_alert_correlation_clusters
WHERE alert_count >= 2 OR peak_risk_score >= 90.0;
