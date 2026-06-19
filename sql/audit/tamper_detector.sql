-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/audit/tamper_detector.sql
-- Description: Out-of-band tamper detection query, cryptographic broken-chain
--              locator, and forensic ledger discrepancy identification in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Forensic Audit Discrepancy Locator View
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_forensic_tamper_discrepancies AS
WITH audit_stream AS (
    SELECT
        block_height,
        event_timestamp,
        actor_arn,
        action_type,
        target_entity_arn,
        previous_block_hash,
        current_block_hash,
        LAG(current_block_hash, 1) OVER (ORDER BY block_height) AS lag_hash,
        LAG(block_height, 1) OVER (ORDER BY block_height) AS lag_height
    FROM audit_crypto_ledger
)
SELECT
    block_height,
    event_timestamp,
    actor_arn,
    action_type,
    target_entity_arn,
    previous_block_hash,
    current_block_hash,
    lag_hash AS expected_parent_hash,
    CASE
        -- Genesis block check
        WHEN block_height = 0 AND previous_block_hash <> '0000000000000000000000000000000000000000000000000000000000000000'
            THEN 'TAMPER_CORRUPTED_GENESIS_BLOCK'
        -- Missing block check (Row deletion)
        WHEN lag_height IS NOT NULL AND block_height <> (lag_height + 1)
            THEN 'TAMPER_DELETED_INTERMEDIATE_BLOCKS'
        -- Broken cryptographic link (Row mutation)
        WHEN lag_hash IS NOT NULL AND previous_block_hash <> lag_hash
            THEN 'TAMPER_BROKEN_CRYPTOGRAPHIC_POINTER'
        ELSE 'VALID_VERIFIED_BLOCK'
    END AS forensic_verdict
FROM audit_stream;

-- ----------------------------------------------------------------------------
-- Comprehensive Ledger Verification Health Status
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_audit_health_summary AS
SELECT
    COUNT(*) AS total_ledger_blocks,
    SUM(CASE WHEN forensic_verdict = 'VALID_VERIFIED_BLOCK' THEN 1 ELSE 0 END) AS valid_block_count,
    SUM(CASE WHEN forensic_verdict <> 'VALID_VERIFIED_BLOCK' THEN 1 ELSE 0 END) AS tampered_block_count,
    CASE
        WHEN SUM(CASE WHEN forensic_verdict <> 'VALID_VERIFIED_BLOCK' THEN 1 ELSE 0 END) = 0 THEN 'LEDGER_INTEGRITY_VERIFIED_CLEAN'
        ELSE 'CRITICAL_OUT_OF_BAND_TAMPER_DETECTED'
    END AS ledger_integrity_status
FROM v_forensic_tamper_discrepancies;
