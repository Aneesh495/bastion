-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/audit/hash_chain.sql
-- Description: Recursive SHA-256 cryptographic hash-chain generation and state
--              accumulator in ANSI SQL / DuckDB.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Cryptographic Hash-Chain Generation Model
-- ----------------------------------------------------------------------------
-- Verifies or recalculates the SHA-256 hash chain:
--   H_0 = sha256("00000000" || block_0_content)
--   H_k = sha256(H_{k-1} || block_k_content)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_audit_recomputed_hash_chain AS
SELECT
    block_height,
    event_timestamp,
    actor_arn,
    action_type,
    target_entity_arn,
    previous_block_hash,
    current_block_hash,
    -- Locally recomputed SHA-256 digest of row payload
    sha256(
        previous_block_hash || '|' ||
        CAST(block_height AS VARCHAR) || '|' ||
        CAST(event_timestamp AS VARCHAR) || '|' ||
        actor_arn || '|' ||
        action_type || '|' ||
        target_entity_arn || '|' ||
        payload_after
    ) AS recomputed_hash,
    CASE
        WHEN current_block_hash = sha256(
            previous_block_hash || '|' ||
            CAST(block_height AS VARCHAR) || '|' ||
            CAST(event_timestamp AS VARCHAR) || '|' ||
            actor_arn || '|' ||
            action_type || '|' ||
            target_entity_arn || '|' ||
            payload_after
        ) THEN 'VALID'
        ELSE 'CORRUPTED_OR_TAMPERED'
    END AS hash_validation_status
FROM audit_crypto_ledger;
