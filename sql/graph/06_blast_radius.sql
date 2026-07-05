-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/graph/blast_radius.sql
-- Description: Transitive blast radius quantification, compromise exposure
--              valuation, and automated containment impact modeling in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Transitive Asset Exposure from Compromised Seed Nodes
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_asset_compromise_blast_radius AS
WITH RECURSIVE reachable_assets AS (
    -- Base case: assets directly marked as compromised or quarantined
    SELECT
        a.asset_id AS compromised_seed_id,
        a.hostname AS compromised_seed_name,
        a.asset_id AS exposed_asset_id,
        a.hostname AS exposed_hostname,
        a.is_crown_jewel,
        a.criticality_score,
        0 AS hop_distance,
        a.hostname AS containment_boundary_path
    FROM core_compute_assets a
    WHERE a.is_compromised = TRUE

    UNION ALL

    -- Recursive reachability across network flow adjacencies
    SELECT
        ra.compromised_seed_id,
        ra.compromised_seed_name,
        e.target_asset_id AS exposed_asset_id,
        e.target_hostname AS exposed_hostname,
        e.target_is_crown_jewel AS is_crown_jewel,
        tgt_a.criticality_score,
        ra.hop_distance + 1 AS hop_distance,
        ra.containment_boundary_path || ' -> ' || e.target_hostname AS containment_boundary_path
    FROM reachable_assets ra
    JOIN v_lateral_movement_edges e ON ra.exposed_asset_id = e.source_asset_id
    JOIN core_compute_assets tgt_a ON e.target_asset_id = tgt_a.asset_id
    WHERE ra.hop_distance < 4
      AND INSTR(ra.containment_boundary_path, e.target_hostname) = 0
)
SELECT
    compromised_seed_id,
    compromised_seed_name,
    COUNT(DISTINCT exposed_asset_id) AS total_exposed_assets,
    COUNT(DISTINCT CASE WHEN is_crown_jewel = TRUE THEN exposed_asset_id END) AS exposed_crown_jewels,
    SUM(criticality_score) AS cumulative_criticality_exposure,
    MAX(hop_distance) AS maximum_compromise_depth,
    CASE
        WHEN COUNT(DISTINCT CASE WHEN is_crown_jewel = TRUE THEN exposed_asset_id END) > 0 THEN 'CATASTROPHIC_TIER_1_EXPOSURE'
        WHEN COUNT(DISTINCT exposed_asset_id) >= 5 THEN 'HIGH_LATERAL_DIFFUSION'
        ELSE 'CONTAINED_BLAST_RADIUS'
    END AS blast_radius_severity
FROM reachable_assets
GROUP BY compromised_seed_id, compromised_seed_name;

-- ----------------------------------------------------------------------------
-- 2. Data Classification Exposure (PII and Confidential Buckets at Risk)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_data_store_blast_radius AS
SELECT
    b.compromised_seed_name,
    s.bucket_id,
    s.bucket_name,
    s.data_classification,
    s.is_publicly_readable,
    CASE
        WHEN s.data_classification = 'RESTRICTED_PII' THEN 'SEVERE_REGULATORY_BREACH_RISK'
        WHEN s.data_classification = 'CONFIDENTIAL' THEN 'CONFIDENTIAL_DATA_LEAKAGE_RISK'
        ELSE 'LOW_IMPACT'
    END AS regulatory_hazard_tier
FROM v_asset_compromise_blast_radius b
CROSS JOIN core_storage_buckets s
WHERE s.account_id IN (
    SELECT DISTINCT account_id FROM core_compute_assets WHERE hostname = b.compromised_seed_name
);
