-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/entity_resolution/asset_correlation.sql
-- Description: Temporal asset correlation across DHCP leases, MAC addresses,
--              transient IP reassignment, and canonical workload identification.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Ephemeral IP Lease Interval Tracking
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS entity_asset_ip_leases (
    lease_id            VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    ip_address          VARCHAR(64) NOT NULL,
    mac_address         VARCHAR(32) NOT NULL,
    lease_start         TIMESTAMP NOT NULL,
    lease_end           TIMESTAMP,                  -- NULL indicates active current lease
    interface_id        VARCHAR(64) NOT NULL,
    is_primary          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_lease_interval CHECK (lease_end IS NULL OR lease_end > lease_start)
);

-- ----------------------------------------------------------------------------
-- 2. Temporal Asset Stitching View
-- ----------------------------------------------------------------------------
-- Resolves any given network flow record to the true underlying compute asset
-- that held the source IP address at the exact instant the flow occurred.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_temporal_stitched_flows AS
SELECT
    f.flow_id,
    f.start_time,
    f.end_time,
    f.src_addr,
    f.dst_addr,
    f.dst_port,
    f.bytes_transferred,
    f.action,
    -- Source Asset Resolution
    COALESCE(l_src.asset_id, a_src.asset_id) AS resolved_source_asset_id,
    COALESCE(a_src_lease.hostname, a_src.hostname, 'UNRESOLVED_EXTERNAL_OR_EPHEMERAL') AS source_hostname,
    COALESCE(a_src_lease.criticality_score, a_src.criticality_score, 0.0) AS source_criticality,
    -- Target Asset Resolution
    COALESCE(l_dst.asset_id, a_dst.asset_id) AS resolved_target_asset_id,
    COALESCE(a_dst_lease.hostname, a_dst.hostname, 'UNRESOLVED_EXTERNAL_OR_EPHEMERAL') AS target_hostname,
    COALESCE(a_dst_lease.criticality_score, a_dst.criticality_score, 0.0) AS target_criticality
FROM telemetry_vpc_flow_logs f
-- Match via historical DHCP lease
LEFT JOIN entity_asset_ip_leases l_src
  ON f.src_addr = l_src.ip_address
 AND f.start_time >= l_src.lease_start
 AND (l_src.lease_end IS NULL OR f.start_time <= l_src.lease_end)
LEFT JOIN core_compute_assets a_src_lease ON l_src.asset_id = a_src_lease.asset_id
-- Fallback match via static primary IP
LEFT JOIN core_compute_assets a_src ON f.src_addr = a_src.primary_ip
-- Destination resolution
LEFT JOIN entity_asset_ip_leases l_dst
  ON f.dst_addr = l_dst.ip_address
 AND f.start_time >= l_dst.lease_start
 AND (l_dst.lease_end IS NULL OR f.start_time <= l_dst.lease_end)
LEFT JOIN core_compute_assets a_dst_lease ON l_dst.asset_id = a_dst_lease.asset_id
LEFT JOIN core_compute_assets a_dst ON f.dst_addr = a_dst.primary_ip;

-- ----------------------------------------------------------------------------
-- 3. IP Reassignment Anomaly Detector
-- ----------------------------------------------------------------------------
-- Detects rapid IP churn or conflicting leases where multiple assets claim
-- the identical IP address within overlapping temporal windows.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_ip_lease_conflicts AS
SELECT
    l1.ip_address,
    l1.asset_id AS asset_id_1,
    l2.asset_id AS asset_id_2,
    l1.lease_start AS lease_start_1,
    l2.lease_start AS lease_start_2,
    'OVERLAPPING_IP_LEASE_CONFLICT' AS anomaly_type
FROM entity_asset_ip_leases l1
JOIN entity_asset_ip_leases l2
  ON l1.ip_address = l2.ip_address
 AND l1.asset_id < l2.asset_id
 AND l1.lease_start <= COALESCE(l2.lease_end, CURRENT_TIMESTAMP)
 AND l2.lease_start <= COALESCE(l1.lease_end, CURRENT_TIMESTAMP);
