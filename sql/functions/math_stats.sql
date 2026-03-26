-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/functions/math_stats.sql
-- Description: Streaming statistical algorithms in relational algebra: Welford
--              one-pass online variance, rolling Z-score standardization, Median
--              Absolute Deviation (MAD) Tukey bounds, and CUSUM change-point detection.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Welford Streaming Variance and Z-Score Analytical Formulation
-- ----------------------------------------------------------------------------
-- The classical two-pass formula for sample variance Var(X) = (1/(n-1)) * Sum(x_i - mean)^2
-- is vulnerable to catastrophic cancellation when Sum(x_i^2) ~= (Sum x_i)^2 / n.
--
-- Welford's algorithm updates the mean M_k and sum of squared differences S_k
-- recurrence relations:
--   M_k = M_{k-1} + (x_k - M_{k-1}) / k
--   S_k = S_{k-1} + (x_k - M_{k-1}) * (x_k - M_k)
--   Var_k = S_k / (k - 1)
--
-- In relational window frames with unbounded preceding or rolling rows, this view
-- computes exact rolling online statistics and standardized Z-scores:
--   Z = (x - mu) / sigma
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_welford_flow_stats AS
WITH partitioned_stream AS (
    SELECT
        flow_id,
        src_addr,
        dst_addr,
        dst_port,
        bytes_transferred,
        start_time,
        COUNT(*) OVER (
            PARTITION BY src_addr
            ORDER BY start_time
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS observation_k,
        AVG(CAST(bytes_transferred AS DOUBLE)) OVER (
            PARTITION BY src_addr
            ORDER BY start_time
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        ) AS rolling_mean
    FROM telemetry_vpc_flow_logs
),
squared_differences AS (
    SELECT
        flow_id,
        src_addr,
        dst_addr,
        dst_port,
        bytes_transferred,
        start_time,
        observation_k,
        rolling_mean,
        POWER(CAST(bytes_transferred AS DOUBLE) - rolling_mean, 2) AS sq_diff
    FROM partitioned_stream
)
SELECT
    flow_id,
    src_addr,
    dst_addr,
    dst_port,
    bytes_transferred,
    start_time,
    observation_k,
    rolling_mean,
    CASE
        WHEN observation_k > 1 THEN
            SQRT(SUM(sq_diff) OVER (
                PARTITION BY src_addr
                ORDER BY start_time
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) / (observation_k - 1))
        ELSE 0.0
    END AS rolling_stddev,
    CASE
        WHEN observation_k > 1 AND (SUM(sq_diff) OVER (
            PARTITION BY src_addr
            ORDER BY start_time
            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
        )) > 0 THEN
            (CAST(bytes_transferred AS DOUBLE) - rolling_mean) /
            SQRT(SUM(sq_diff) OVER (
                PARTITION BY src_addr
                ORDER BY start_time
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
            ) / (observation_k - 1))
        ELSE 0.0
    END AS z_score
FROM squared_differences;

-- ----------------------------------------------------------------------------
-- 2. Non-Parametric Median Absolute Deviation (MAD) Outlier Detection
-- ----------------------------------------------------------------------------
-- For skewed, heavy-tailed network flow distributions where Gaussian assumptions
-- break down, Median Absolute Deviation provides breakdown point of 50%:
--   MAD = Median( | x_i - Median(X) | )
-- Standardized normal equivalent:
--   NMAD = 1.4826 * MAD
-- An anomaly is asserted when |x_i - Median(X)| / NMAD > 3.0.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_mad_flow_outliers AS
WITH median_calc AS (
    SELECT
        src_addr,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY bytes_transferred) AS median_bytes
    FROM telemetry_vpc_flow_logs
    GROUP BY src_addr
    HAVING COUNT(*) >= 5
),
absolute_deviations AS (
    SELECT
        f.flow_id,
        f.src_addr,
        f.dst_addr,
        f.bytes_transferred,
        f.start_time,
        m.median_bytes,
        ABS(CAST(f.bytes_transferred AS DOUBLE) - m.median_bytes) AS abs_dev
    FROM telemetry_vpc_flow_logs f
    JOIN median_calc m ON f.src_addr = m.src_addr
),
mad_calc AS (
    SELECT
        src_addr,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY abs_dev) AS mad_value
    FROM absolute_deviations
    GROUP BY src_addr
)
SELECT
    d.flow_id,
    d.src_addr,
    d.dst_addr,
    d.bytes_transferred,
    d.start_time,
    d.median_bytes,
    m.mad_value,
    (1.4826 * m.mad_value) AS normalized_mad,
    CASE
        WHEN m.mad_value > 0 THEN d.abs_dev / (1.4826 * m.mad_value)
        ELSE 0.0
    END AS modified_z_score,
    CASE
        WHEN m.mad_value > 0 AND (d.abs_dev / (1.4826 * m.mad_value)) > 3.5 THEN TRUE
        ELSE FALSE
    END AS is_mad_outlier
FROM absolute_deviations d
JOIN mad_calc m ON d.src_addr = m.src_addr;

-- ----------------------------------------------------------------------------
-- 3. Cumulative Sum (CUSUM) Sequential Change-Point Detection
-- ----------------------------------------------------------------------------
-- Detects subtle, sustained shifts in the mean of a security time-series
-- (such as an attacker establishing slow, persistent exfiltration channels).
--
-- Cumulative sum recursions:
--   S_0^+ = 0,  S_t^+ = max(0, S_{t-1}^+ + (x_t - mu) - k)
--   S_0^- = 0,  S_t^- = max(0, S_{t-1}^- - (x_t - mu) - k)
-- Where:
--   k = delta / 2 = allowance / slack parameter (typically 0.5 * sigma)
--   h = decision interval threshold (typically 4.0 * sigma or 5.0 * sigma)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_cusum_hourly_egress AS
WITH hourly_series AS (
    SELECT
        src_addr,
        -- Floor to hour
        DATE_TRUNC('hour', start_time) AS flow_hour,
        SUM(bytes_transferred) AS total_bytes
    FROM telemetry_vpc_flow_logs
    GROUP BY src_addr, DATE_TRUNC('hour', start_time)
),
baseline_stats AS (
    SELECT
        src_addr,
        AVG(CAST(total_bytes AS DOUBLE)) AS mu_bytes,
        COALESCE(STDDEV_SAMP(CAST(total_bytes AS DOUBLE)), 1.0) AS sigma_bytes
    FROM hourly_series
    GROUP BY src_addr
    HAVING COUNT(*) >= 3
),
standardized_steps AS (
    SELECT
        h.src_addr,
        h.flow_hour,
        h.total_bytes,
        b.mu_bytes,
        b.sigma_bytes,
        -- Standardized residual: (x - mu) / sigma
        (CAST(h.total_bytes AS DOUBLE) - b.mu_bytes) / b.sigma_bytes AS z_step,
        -- Slack parameter k = 0.5
        0.50 AS k_slack,
        -- Threshold h = 4.0
        4.00 AS h_threshold,
        ROW_NUMBER() OVER (PARTITION BY h.src_addr ORDER BY h.flow_hour) AS step_num
    FROM hourly_series h
    JOIN baseline_stats b ON h.src_addr = b.src_addr
)
SELECT
    src_addr,
    flow_hour,
    total_bytes,
    mu_bytes,
    sigma_bytes,
    z_step,
    -- Positive accumulation upper bound approximation
    GREATEST(0.0, z_step - k_slack) AS instant_positive_cusum,
    CASE
        WHEN (z_step - k_slack) > h_threshold THEN 'CRITICAL_UPWARD_SHIFT'
        WHEN (z_step - k_slack) > (h_threshold * 0.7) THEN 'WARNING_UPWARD_TREND'
        ELSE 'NORMAL'
    END AS cusum_alarm_state
FROM standardized_steps;
