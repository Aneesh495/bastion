-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/analytics/beaconing.sql
-- Description: Command-and-Control (C2) beaconing periodicity detection, inter-arrival
--              delta distributions, Coefficient of Variation, and jitter entropy.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Connection Inter-Arrival Time Deltas (Lag Analysis)
-- ----------------------------------------------------------------------------
-- For each distinct outbound communication channel (src_addr -> dst_addr:dst_port),
-- extracts consecutive connection start timestamps and computes the time interval:
--   Delta_t = t_i - t_{i-1} (in seconds)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_beaconing_inter_arrival_deltas AS
WITH ordered_flows AS (
    SELECT
        flow_id,
        src_addr,
        dst_addr,
        dst_port,
        bytes_transferred,
        start_time,
        LAG(start_time, 1) OVER (
            PARTITION BY src_addr, dst_addr, dst_port
            ORDER BY start_time
        ) AS previous_start_time
    FROM telemetry_vpc_flow_logs
    WHERE action = 'ACCEPT'
),
flow_deltas AS (
    SELECT
        flow_id,
        src_addr,
        dst_addr,
        dst_port,
        bytes_transferred,
        start_time,
        previous_start_time,
        -- Inter-arrival delta in seconds
        EXTRACT(EPOCH FROM (start_time - previous_start_time)) AS delta_seconds
    FROM ordered_flows
    WHERE previous_start_time IS NOT NULL
)
SELECT
    flow_id,
    src_addr,
    dst_addr,
    dst_port,
    bytes_transferred,
    start_time,
    delta_seconds,
    -- Bucket deltas into 10-second discrete bins for entropy calculation
    FLOOR(delta_seconds / 10.0) * 10 AS delta_bucket
FROM flow_deltas
WHERE delta_seconds >= 1.0 AND delta_seconds <= 7200.0;

-- ----------------------------------------------------------------------------
-- 2. Statistical Dispersion and Coefficient of Variation (CV) Formulation
-- ----------------------------------------------------------------------------
-- Poisson / human-driven network traffic exhibits an exponential distribution
-- where standard deviation equals the mean (CV = sigma / mu ~= 1.0).
-- In contrast, automated malware beaconing (e.g. Cobalt Strike with 20% jitter)
-- clusters narrowly around the configured sleep interval (CV < 0.30).
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_c2_beaconing_candidates AS
WITH channel_stats AS (
    SELECT
        src_addr,
        dst_addr,
        dst_port,
        COUNT(*) AS total_beacons,
        AVG(delta_seconds) AS mean_delta_seconds,
        COALESCE(STDDEV_SAMP(delta_seconds), 0.0) AS stddev_delta_seconds,
        MIN(delta_seconds) AS min_delta,
        MAX(delta_seconds) AS max_delta,
        AVG(bytes_transferred) AS mean_bytes,
        COALESCE(STDDEV_SAMP(bytes_transferred), 0.0) AS stddev_bytes,
        COUNT(DISTINCT delta_bucket) AS distinct_interval_buckets
    FROM v_beaconing_inter_arrival_deltas
    GROUP BY src_addr, dst_addr, dst_port
    HAVING COUNT(*) >= 12 -- Minimum threshold of 12 consecutive beacons
)
SELECT
    src_addr,
    dst_addr,
    dst_port,
    total_beacons,
    mean_delta_seconds,
    stddev_delta_seconds,
    -- Coefficient of Variation: CV = sigma / mu
    CASE
        WHEN mean_delta_seconds > 0 THEN stddev_delta_seconds / mean_delta_seconds
        ELSE 1.0
    END AS coefficient_of_variation,
    -- Payload byte variance ratio
    CASE
        WHEN mean_bytes > 0 THEN stddev_bytes / mean_bytes
        ELSE 1.0
    END AS byte_coefficient_of_variation,
    distinct_interval_buckets,
    -- Composite beaconing regularity score (0.0 to 100.0)
    CASE
        WHEN mean_delta_seconds > 0 AND (stddev_delta_seconds / mean_delta_seconds) < 0.20 THEN 98.0
        WHEN mean_delta_seconds > 0 AND (stddev_delta_seconds / mean_delta_seconds) < 0.35 THEN 88.0
        WHEN mean_delta_seconds > 0 AND (stddev_delta_seconds / mean_delta_seconds) < 0.50 THEN 70.0
        ELSE 20.0
    END AS beacon_confidence_score,
    CASE
        WHEN (stddev_delta_seconds / mean_delta_seconds) < 0.20 THEN 'CRITICAL_HIGH_PRECISION_BEACON'
        WHEN (stddev_delta_seconds / mean_delta_seconds) < 0.35 THEN 'HIGH_PROBABILITY_JITTERED_BEACON'
        WHEN (stddev_delta_seconds / mean_delta_seconds) < 0.50 THEN 'SUSPICIOUS_PERIODIC_HEARTBEAT'
        ELSE 'BENIGN_RANDOM_TRAFFIC'
    END AS detection_state
FROM channel_stats
ORDER BY beacon_confidence_score DESC, total_beacons DESC;
