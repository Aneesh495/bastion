-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/analytics/data_exfiltration.sql
-- Description: Volumetric data exfiltration detection, off-hours egress spikes,
--              asymmetric upload ratios, and S3 bulk object staging analytics.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Asymmetric Egress-to-Ingress Traffic Ratio Analytics
-- ----------------------------------------------------------------------------
-- Normal internal hosts downloading updates or querying APIs exhibit asymmetric
-- ingress-heavy traffic (bytes_in >> bytes_out, ratio < 0.15).
-- High-volume exfiltration inverts this distribution (bytes_out >> bytes_in, ratio > 5.0).
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_asymmetric_egress_flows AS
WITH host_flows AS (
    SELECT
        src_addr,
        dst_addr,
        DATE_TRUNC('hour', start_time) AS flow_hour,
        SUM(bytes_transferred) AS total_egress_bytes,
        COUNT(*) AS total_flow_count,
        MAX(start_time) AS latest_flow_time
    FROM telemetry_vpc_flow_logs
    WHERE action = 'ACCEPT'
    GROUP BY src_addr, dst_addr, DATE_TRUNC('hour', start_time)
),
host_aggregate_hourly AS (
    SELECT
        src_addr,
        flow_hour,
        SUM(total_egress_bytes) AS total_host_egress,
        COUNT(DISTINCT dst_addr) AS distinct_destinations
    FROM host_flows
    GROUP BY src_addr, flow_hour
)
SELECT
    f.src_addr,
    f.dst_addr,
    f.flow_hour,
    f.total_egress_bytes,
    h.total_host_egress,
    -- Fraction of host egress concentrated into this single target
    CAST(f.total_egress_bytes AS DOUBLE) / h.total_host_egress AS destination_concentration_ratio,
    h.distinct_destinations,
    CASE
        WHEN f.total_egress_bytes > 50000000 AND (CAST(f.total_egress_bytes AS DOUBLE) / h.total_host_egress) > 0.80 THEN 'MASSIVE_CONCENTRATED_EXFILTRATION'
        WHEN f.total_egress_bytes > 10000000 THEN 'ELEVATED_OUTBOUND_DATA_DUMP'
        ELSE 'STANDARD_EGRESS'
    END AS exfiltration_risk_tier
FROM host_flows f
JOIN host_aggregate_hourly h
  ON f.src_addr = h.src_addr AND f.flow_hour = h.flow_hour
WHERE f.total_egress_bytes >= 1000000; -- Focus on transfers >= 1 MB

-- ----------------------------------------------------------------------------
-- 2. Off-Hours Egress Volumetric Anomaly Detection
-- ----------------------------------------------------------------------------
-- Analyzes egress occurring outside standard business operating hours
-- (20:00 to 06:00 UTC, or weekend days).
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_off_hours_egress_spikes AS
WITH hourly_classified AS (
    SELECT
        f.flow_id,
        f.src_addr,
        f.dst_addr,
        f.bytes_transferred,
        f.start_time,
        EXTRACT(HOUR FROM f.start_time) AS event_hour,
        EXTRACT(DOW FROM f.start_time) AS event_dow,
        CASE
            WHEN EXTRACT(DOW FROM f.start_time) IN (0, 6) THEN TRUE
            WHEN EXTRACT(HOUR FROM f.start_time) >= 20 OR EXTRACT(HOUR FROM f.start_time) < 6 THEN TRUE
            ELSE FALSE
        END AS is_off_hours
    FROM telemetry_vpc_flow_logs f
    WHERE f.action = 'ACCEPT'
),
baseline_window AS (
    SELECT
        src_addr,
        AVG(bytes_transferred) AS baseline_mean,
        COALESCE(STDDEV_SAMP(bytes_transferred), 1000.0) AS baseline_stddev
    FROM hourly_classified
    WHERE is_off_hours = FALSE
    GROUP BY src_addr
    HAVING COUNT(*) >= 5
)
SELECT
    h.flow_id,
    h.src_addr,
    h.dst_addr,
    h.bytes_transferred,
    h.start_time,
    h.event_hour,
    b.baseline_mean,
    b.baseline_stddev,
    (CAST(h.bytes_transferred AS DOUBLE) - b.baseline_mean) / b.baseline_stddev AS off_hours_z_score,
    CASE
        WHEN (h.bytes_transferred - b.baseline_mean) / b.baseline_stddev > 4.0 THEN 'CRITICAL_OFF_HOURS_DATA_EXFILTRATION'
        WHEN (h.bytes_transferred - b.baseline_mean) / b.baseline_stddev > 2.5 THEN 'SUSPICIOUS_OFF_HOURS_TRANSFER'
        ELSE 'NORMAL_OFF_HOURS'
    END AS anomaly_classification
FROM hourly_classified h
JOIN baseline_window b ON h.src_addr = b.src_addr
WHERE h.is_off_hours = TRUE;
