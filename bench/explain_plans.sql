-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: bench/explain_plans.sql
-- Description: Relational query execution plan diagnostics, join order inspection,
--              predicate pushdown verification, and index utilization analysis.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Diagnostic 1: Execution Plan for Recursive Lateral Movement Graph Traversal
-- ----------------------------------------------------------------------------

EXPLAIN
SELECT
    origin_asset_id,
    destination_hostname,
    hop_count,
    risk_classification
FROM v_active_lateral_attack_paths
WHERE breaches_crown_jewel = TRUE;

-- ----------------------------------------------------------------------------
-- Diagnostic 2: Execution Plan for IAM Privilege Escalation Primitives
-- ----------------------------------------------------------------------------

EXPLAIN
SELECT
    principal_id,
    escalation_primitive,
    risk_score
FROM v_iam_privilege_escalation_paths
WHERE risk_score >= 80.0;

-- ----------------------------------------------------------------------------
-- Diagnostic 3: Execution Plan for Periodic C2 Beaconing Variance Analysis
-- ----------------------------------------------------------------------------

EXPLAIN
SELECT
    src_addr,
    dst_addr,
    coefficient_of_variation,
    detection_state
FROM v_c2_beaconing_candidates
WHERE detection_state LIKE '%CRITICAL%';

-- ----------------------------------------------------------------------------
-- Diagnostic 4: Execution Plan for Multi-Tactic Alert Orchestrator and Suppression
-- ----------------------------------------------------------------------------

EXPLAIN
SELECT
    rule_code,
    entity_id,
    severity,
    title
FROM v_unsuppressed_findings
WHERE severity = 'CRITICAL';

-- ----------------------------------------------------------------------------
-- Diagnostic 5: Execution Plan for Multi-Stage Kill-Chain Campaign Progression
-- ----------------------------------------------------------------------------

EXPLAIN
SELECT
    entity_type,
    entity_id,
    distinct_tactics_count,
    kill_chain_stage
FROM v_entity_kill_chain_progression;

-- ----------------------------------------------------------------------------
-- Diagnostic 6: Execution Plan for Cryptographic Ledger Hash Verification
-- ----------------------------------------------------------------------------

EXPLAIN
SELECT
    total_ledger_blocks,
    valid_block_count,
    ledger_integrity_status
FROM v_audit_health_summary;
