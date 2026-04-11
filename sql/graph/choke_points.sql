-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/graph/choke_points.sql
-- Description: Network choke point identification, betweenness centrality
--              approximation, and single-point-of-failure bridge analysis in SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Intermediate Node Transit Frequency (Betweenness Centrality Proxy)
-- ----------------------------------------------------------------------------
-- An intermediate compute asset or network gateway through which multiple
-- disparate lateral movement attack trajectories must transit represents a
-- high-value defensive choke point: hardening or isolating this node severs
-- multiple concurrent threat vectors.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_network_choke_points AS
WITH path_nodes AS (
    SELECT
        origin_asset_id,
        origin_hostname,
        destination_asset_id,
        destination_hostname,
        full_path_trace,
        breaches_crown_jewel,
        a.asset_id AS intermediate_asset_id,
        a.hostname AS intermediate_hostname,
        a.subnet_id,
        a.criticality_score
    FROM v_active_lateral_attack_paths p
    CROSS JOIN core_compute_assets a
    -- Test if asset is an intermediate transit hop in the attack path trace
    WHERE INSTR(p.full_path_trace, a.hostname) > 0
      AND a.hostname <> p.origin_hostname
      AND a.hostname <> p.destination_hostname
),
choke_point_aggregates AS (
    SELECT
        intermediate_asset_id AS asset_id,
        intermediate_hostname AS hostname,
        COUNT(DISTINCT full_path_trace) AS total_paths_traversed,
        COUNT(DISTINCT CASE WHEN breaches_crown_jewel = TRUE THEN full_path_trace END) AS crown_jewel_paths_traversed,
        COUNT(DISTINCT origin_asset_id) AS distinct_origins_intercepted,
        COUNT(DISTINCT destination_asset_id) AS distinct_targets_shielded,
        AVG(criticality_score) AS asset_criticality
    FROM path_nodes
    GROUP BY intermediate_asset_id, intermediate_hostname
),
total_paths_metric AS (
    SELECT COUNT(*) AS global_attack_path_count
    FROM v_active_lateral_attack_paths
)
SELECT
    c.asset_id,
    c.hostname,
    c.total_paths_traversed,
    c.crown_jewel_paths_traversed,
    c.distinct_origins_intercepted,
    c.distinct_targets_shielded,
    g.global_attack_path_count,
    -- Ratio of total attack paths passing through this single node
    CASE
        WHEN g.global_attack_path_count > 0 THEN
            CAST(c.total_paths_traversed AS DOUBLE) / g.global_attack_path_count
        ELSE 0.0
    END AS betweenness_path_ratio,
    CASE
        WHEN c.crown_jewel_paths_traversed >= 3 THEN 'CRITICAL_SECURITY_CHOKEPOINT'
        WHEN c.total_paths_traversed >= 2 THEN 'HIGH_TRANSIT_PIVOT_HOST'
        ELSE 'INTERMEDIATE_RELAY'
    END AS chokepoint_tier
FROM choke_point_aggregates c
CROSS JOIN total_paths_metric g
ORDER BY c.crown_jewel_paths_traversed DESC, c.total_paths_traversed DESC;
