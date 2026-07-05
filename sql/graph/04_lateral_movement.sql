-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/graph/lateral_movement.sql
-- Description: Multi-hop lateral movement attack path discovery, DMZ-to-Crown-Jewel
--              reachability, and recursive path synthesis with cycle elimination.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Topological Adjacency and Ingress Reachability Edges
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_lateral_movement_edges AS
-- Physical network flow reachability observed in telemetry
SELECT DISTINCT
    src_a.asset_id AS source_asset_id,
    src_a.hostname AS source_hostname,
    src_sub.zone_type AS source_zone,
    dst_a.asset_id AS target_asset_id,
    dst_a.hostname AS target_hostname,
    dst_sub.zone_type AS target_zone,
    dst_a.is_crown_jewel AS target_is_crown_jewel,
    f.dst_port,
    'OBSERVED_NETWORK_FLOW' AS transition_mechanism,
    1.0000 AS base_hop_cost
FROM telemetry_vpc_flow_logs f
JOIN core_compute_assets src_a ON f.src_addr = src_a.primary_ip
JOIN core_subnets src_sub ON src_a.subnet_id = src_sub.subnet_id
JOIN core_compute_assets dst_a ON f.dst_addr = dst_a.primary_ip
JOIN core_subnets dst_sub ON dst_a.subnet_id = dst_sub.subnet_id
WHERE f.action = 'ACCEPT'
  AND src_a.asset_id <> dst_a.asset_id

UNION

-- Static graph edges defined in architecture
SELECT
    src.node_id AS source_asset_id,
    src.display_name AS source_hostname,
    'INTERNAL' AS source_zone,
    tgt.node_id AS target_asset_id,
    tgt.display_name AS target_hostname,
    'INTERNAL' AS target_zone,
    CASE WHEN tgt.criticality_tier = 1 THEN TRUE ELSE FALSE END AS target_is_crown_jewel,
    22 AS dst_port,
    e.edge_type AS transition_mechanism,
    CAST(e.edge_weight AS DOUBLE) AS base_hop_cost
FROM graph_edges e
JOIN graph_nodes src ON e.source_node_id = src.node_id
JOIN graph_nodes tgt ON e.target_node_id = tgt.node_id
WHERE e.edge_type IN ('NETWORK_INGRESS', 'CONTAINS_ASSET', 'CAN_ASSUME_ROLE')
  AND e.is_active = TRUE;

-- ----------------------------------------------------------------------------
-- 2. Recursive Multi-Hop Attack Path Synthesis
-- ----------------------------------------------------------------------------
-- Traverses reachable paths starting from internet-facing DMZ systems or
-- compromised hosts, searching for paths terminating in Tier 1 Crown Jewels.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_active_lateral_attack_paths AS
WITH RECURSIVE attack_paths AS (
    -- Base case: 1-hop outbound transitions from DMZ or compromised assets
    SELECT
        e.source_asset_id AS origin_asset_id,
        e.source_hostname AS origin_hostname,
        e.target_asset_id AS current_asset_id,
        e.target_hostname AS current_hostname,
        e.target_zone AS current_zone,
        e.target_is_crown_jewel,
        1 AS hop_count,
        e.base_hop_cost AS cumulative_cost,
        e.source_hostname || ' -> (' || e.transition_mechanism || ':' || CAST(e.dst_port AS VARCHAR) || ') -> ' || e.target_hostname AS full_path_trace
    FROM v_lateral_movement_edges e
    WHERE e.source_zone = 'DMZ'

    UNION ALL

    -- Recursive step: extend traversal to adjacent connected targets
    SELECT
        ap.origin_asset_id,
        ap.origin_hostname,
        e.target_asset_id AS current_asset_id,
        e.target_hostname AS current_hostname,
        e.target_zone AS current_zone,
        e.target_is_crown_jewel,
        ap.hop_count + 1 AS hop_count,
        ap.cumulative_cost + e.base_hop_cost AS cumulative_cost,
        ap.full_path_trace || ' -> (' || e.transition_mechanism || ':' || CAST(e.dst_port AS VARCHAR) || ') -> ' || e.target_hostname AS full_path_trace
    FROM attack_paths ap
    JOIN v_lateral_movement_edges e ON ap.current_asset_id = e.source_asset_id
    WHERE ap.hop_count < 5 -- Cap recursion depth to 5 hops
      AND ap.target_is_crown_jewel = FALSE -- Terminate search once Crown Jewel is breached
      -- Cycle guard: prevent revisiting any previously visited host
      AND INSTR(ap.full_path_trace, e.target_hostname) = 0
)
SELECT
    origin_asset_id,
    origin_hostname,
    current_asset_id AS destination_asset_id,
    current_hostname AS destination_hostname,
    hop_count,
    cumulative_cost,
    target_is_crown_jewel AS breaches_crown_jewel,
    full_path_trace,
    CASE
        WHEN target_is_crown_jewel = TRUE AND hop_count <= 2 THEN 'CRITICAL_DIRECT_BREACH_PATH'
        WHEN target_is_crown_jewel = TRUE THEN 'HIGH_MULTI_HOP_BREACH_PATH'
        ELSE 'INTERMEDIATE_LATERAL_PATH'
    END AS risk_classification
FROM attack_paths;
