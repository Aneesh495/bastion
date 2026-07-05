-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/rules/ta9999_orchestrator.sql
-- Description: Unified multi-tactic detection rule orchestrator view, alert
--              suppression evaluation, kill-chain stage progression, and composite scoring.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Global Multi-Tactic Findings Union
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_raw_mitre_findings_union AS
SELECT * FROM v_findings_ta0001
UNION ALL SELECT * FROM v_findings_ta0002
UNION ALL SELECT * FROM v_findings_ta0003
UNION ALL SELECT * FROM v_findings_ta0004
UNION ALL SELECT * FROM v_findings_ta0005
UNION ALL SELECT * FROM v_findings_ta0006
UNION ALL SELECT * FROM v_findings_ta0007
UNION ALL SELECT * FROM v_findings_ta0008
UNION ALL SELECT * FROM v_findings_ta0009
UNION ALL SELECT * FROM v_findings_ta0010
UNION ALL SELECT * FROM v_findings_ta0011
UNION ALL SELECT * FROM v_findings_ta0040;

-- ----------------------------------------------------------------------------
-- 2. Suppression Filtering and Asset Weight Adjustment
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_unsuppressed_findings AS
SELECT
    f.rule_code,
    f.evidence_id,
    f.account_id,
    f.entity_type,
    f.entity_id,
    f.detected_at,
    f.severity,
    f.confidence_score,
    f.composite_risk_score,
    f.title,
    f.summary,
    f.evidence_json,
    f.tactic_code,
    f.technique_code
FROM v_raw_mitre_findings_union f
LEFT JOIN detection_suppressions s
  ON f.entity_type = s.entity_type
 AND f.entity_id = s.entity_id
 AND s.is_active = TRUE
 AND s.expires_at > CURRENT_TIMESTAMP
WHERE s.suppression_id IS NULL;

-- ----------------------------------------------------------------------------
-- 3. Kill-Chain Stage Progression and Advanced Campaign Scoring
-- ----------------------------------------------------------------------------
-- Calculates how many distinct MITRE ATT&CK tactics have triggered against
-- the same entity identity or infrastructure host within a sliding window.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_entity_kill_chain_progression AS
WITH entity_tactics AS (
    SELECT
        entity_type,
        entity_id,
        COUNT(DISTINCT tactic_code) AS distinct_tactics_count,
        COUNT(*) AS total_alert_count,
        MAX(composite_risk_score) AS max_rule_risk_score,
        AVG(composite_risk_score) AS avg_rule_risk_score,
        MIN(detected_at) AS first_signal_at,
        MAX(detected_at) AS latest_signal_at
    FROM v_unsuppressed_findings
    GROUP BY entity_type, entity_id
)
SELECT
    entity_type,
    entity_id,
    distinct_tactics_count,
    total_alert_count,
    first_signal_at,
    latest_signal_at,
    -- Multi-tactic progression multiplier: 1.0 + (0.25 * (distinct_tactics - 1))
    LEAST(100.0, max_rule_risk_score * (1.0 + 0.25 * (distinct_tactics_count - 1))) AS aggregated_campaign_risk_score,
    CASE
        WHEN distinct_tactics_count >= 4 THEN 'STAGE_4_FULL_KILL_CHAIN_BREACH'
        WHEN distinct_tactics_count = 3  THEN 'STAGE_3_ADVANCED_INTRUSION'
        WHEN distinct_tactics_count = 2  THEN 'STAGE_2_ESTABLISHED_FOOTHOLD'
        ELSE 'STAGE_1_INITIAL_ISOLATED_PROBE'
    END AS kill_chain_stage
FROM entity_tactics;

-- ----------------------------------------------------------------------------
-- 4. Prioritized Security Incident Feed
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_prioritized_security_feed AS
SELECT
    f.rule_code,
    f.title,
    f.severity,
    f.tactic_code,
    f.technique_code,
    f.entity_type,
    f.entity_id,
    k.kill_chain_stage,
    k.aggregated_campaign_risk_score,
    f.detected_at,
    f.summary
FROM v_unsuppressed_findings f
JOIN v_entity_kill_chain_progression k
  ON f.entity_type = k.entity_type AND f.entity_id = k.entity_id
ORDER BY k.aggregated_campaign_risk_score DESC, f.detected_at DESC;
