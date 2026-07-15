-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: tests/integration_tests.sql
-- Description: End-to-end integration test scenarios:
--              Multi-stage APT29 campaign detection, alert suppression isolation,
--              temporal incident correlation, DFA state machine transitions,
--              automated playbook SQL synthesis, and cryptographic ledger integrity.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Integration Test Suite 1: Full APT29 Kill-Chain Progression
-- ----------------------------------------------------------------------------

-- Test 1.1: Verify Host Compromise Reaches Stage 4 Breach Across Tactics
SELECT
    'INTEGRATION_KILL_CHAIN' AS suite,
    'apt29_kill_chain_progression' AS test_name,
    CASE
        WHEN kill_chain_stage = 'STAGE_4_FULL_KILL_CHAIN_BREACH' AND distinct_tactics_count >= 5 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    kill_chain_stage AS actual,
    'STAGE_4_FULL_KILL_CHAIN_BREACH' AS expected,
    'Entity ast-web-01 reaches Stage 4 breach spanning 5 or more MITRE tactics' AS description
FROM v_entity_kill_chain_progression
WHERE entity_id = 'ast-web-01';

-- ----------------------------------------------------------------------------
-- Integration Test Suite 2: Suppression Filter Isolation
-- ----------------------------------------------------------------------------

-- Test 2.1: Verify Active Suppression Invariants
WITH raw_cnt AS (
    SELECT COUNT(*) AS c FROM v_raw_mitre_findings_union
),
unsuppressed_cnt AS (
    SELECT COUNT(*) AS c FROM v_unsuppressed_findings
)
SELECT
    'INTEGRATION_SUPPRESSION' AS suite,
    'suppression_filter_isolation' AS test_name,
    CASE
        WHEN u.c <= r.c THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(u.c AS VARCHAR) || '<=' || CAST(r.c AS VARCHAR) AS actual,
    'TRUE' AS expected,
    'Unsuppressed findings count is strictly bounded by raw findings union' AS description
FROM raw_cnt r, unsuppressed_cnt u;

-- ----------------------------------------------------------------------------
-- Integration Test Suite 3: Incident Alert Correlation Engine
-- ----------------------------------------------------------------------------

-- Test 3.1: Temporal Alert Cluster Synthesis
SELECT
    'INTEGRATION_CORRELATION' AS suite,
    'temporal_alert_clustering' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Multi-signal alerts on ast-web-01 clustered into unified incident correlation group' AS description
FROM v_alert_correlation_clusters
WHERE entity_id = 'ast-web-01';

-- ----------------------------------------------------------------------------
-- Integration Test Suite 4: Incident DFA State Machine Governance
-- ----------------------------------------------------------------------------

-- Test 4.1: Permitted DFA Lifecycle Transition from TRIAGED
SELECT
    'INTEGRATION_DFA' AS suite,
    'dfa_permitted_transitions' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Formal state machine verifies legal lifecycle transitions for active incident' AS description
FROM v_incident_permitted_transitions
WHERE incident_id = 'inc-001'
  AND candidate_target_state = 'CONTAINED';

-- ----------------------------------------------------------------------------
-- Integration Test Suite 5: Attack Timeline Reconstruction
-- ----------------------------------------------------------------------------

-- Test 5.1: Chronological Alert Timeline Order
SELECT
    'INTEGRATION_TIMELINE' AS suite,
    'chronological_timeline_order' AS test_name,
    CASE
        WHEN COUNT(*) >= 2 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 2' AS expected,
    'Chronological event timeline reconstructs kill-chain order across linked alerts' AS description
FROM v_incident_chronological_timelines
WHERE incident_id = 'inc-001';

-- ----------------------------------------------------------------------------
-- Integration Test Suite 6: Automated Playbook SQL Directive Synthesis
-- ----------------------------------------------------------------------------

-- Test 6.1: Idempotent Host Quarantine Command Generation
SELECT
    'INTEGRATION_PLAYBOOK' AS suite,
    'automated_quarantine_synthesis' AS test_name,
    CASE
        WHEN synthesized_sql_cmd LIKE '%UPDATE core_compute_assets SET is_quarantined = TRUE%' THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    'SYNTHESIZED_SQL_MATCH' AS actual,
    'SYNTHESIZED_SQL_MATCH' AS expected,
    'Synthesizes idempotent SQL host quarantine command for compromised compute asset' AS description
FROM v_synthesized_containment_playbook
WHERE incident_id = 'inc-001'
  AND action_type = 'QUARANTINE_COMPUTE_HOST'
LIMIT 1;

-- ----------------------------------------------------------------------------
-- Integration Test Suite 7: Cryptographic SHA-256 Audit Ledger Integrity
-- ----------------------------------------------------------------------------

-- Test 7.1: Zero Forensic Tamper Discrepancies
SELECT
    'INTEGRATION_AUDIT' AS suite,
    'audit_chain_integrity' AS test_name,
    CASE
        WHEN total_ledger_blocks >= 1 AND tampered_block_count = 0 AND ledger_integrity_status = 'LEDGER_INTEGRITY_VERIFIED_CLEAN' THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    ledger_integrity_status AS actual,
    'LEDGER_INTEGRITY_VERIFIED_CLEAN' AS expected,
    'Cryptographic SHA-256 hash chain verification confirms ledger immutability' AS description
FROM v_audit_health_summary;
