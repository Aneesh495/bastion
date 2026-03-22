-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/08_audit.sql
-- Description: Tamper-evident cryptographic audit ledger, SHA-256 hash chaining,
--              block checkpoint anchors, and forensic integrity views.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Cryptographic Hash-Chained Audit Ledger
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_crypto_ledger (
    block_height        BIGINT PRIMARY KEY,
    event_timestamp     TIMESTAMP NOT NULL,
    actor_arn           VARCHAR(512) NOT NULL,
    action_type         VARCHAR(64) NOT NULL,
    target_entity_arn   VARCHAR(512) NOT NULL,
    payload_before      TEXT,
    payload_after       TEXT NOT NULL,
    nonce               VARCHAR(32) NOT NULL DEFAULT '00000000',
    previous_block_hash VARCHAR(64) NOT NULL,
    current_block_hash  VARCHAR(64) NOT NULL,
    signature_ed25519   VARCHAR(128),
    CONSTRAINT chk_height_positive CHECK (block_height >= 0)
);

-- ----------------------------------------------------------------------------
-- 2. Periodic State Checkpoints and Merkle Roots
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    checkpoint_id       VARCHAR(64) PRIMARY KEY,
    block_height        BIGINT NOT NULL REFERENCES audit_crypto_ledger(block_height),
    root_merkle_hash    VARCHAR(64) NOT NULL,
    total_ledger_events BIGINT NOT NULL CHECK (total_ledger_events >= 0),
    certified_by_ca     VARCHAR(255) NOT NULL,
    checkpoint_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_anchored_externally BOOLEAN NOT NULL DEFAULT FALSE
);

-- ----------------------------------------------------------------------------
-- 3. Dynamic Forensic Verification View
-- ----------------------------------------------------------------------------

-- Calculates expected hash chain locally and compares against recorded hash
CREATE VIEW IF NOT EXISTS v_audit_integrity_verification AS
SELECT
    cur.block_height,
    cur.event_timestamp,
    cur.actor_arn,
    cur.action_type,
    cur.target_entity_arn,
    cur.previous_block_hash,
    cur.current_block_hash,
    -- Lagged previous block hash from previous physical row
    LAG(cur.current_block_hash, 1) OVER (ORDER BY cur.block_height) AS expected_previous_hash,
    CASE
        WHEN cur.block_height = 0 THEN
            CASE WHEN cur.previous_block_hash = '0000000000000000000000000000000000000000000000000000000000000000' THEN 'VALID_GENESIS' ELSE 'INVALID_GENESIS' END
        WHEN cur.previous_block_hash = LAG(cur.current_block_hash, 1) OVER (ORDER BY cur.block_height) THEN 'CHAIN_INTACT'
        ELSE 'TAMPER_DETECTED_BROKEN_CHAIN'
    END AS chain_integrity_status
FROM audit_crypto_ledger cur;

CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_crypto_ledger(actor_arn, event_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_crypto_ledger(target_entity_arn);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_crypto_ledger(event_timestamp);
