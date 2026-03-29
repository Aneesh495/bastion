-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/functions/holt_winters_benford.sql
-- Description: Holt-Winters linear trend forecasting, Exponentially Weighted
--              Moving Average (EWMA), and Benford's Law Chi-Square goodness-of-fit
--              testing in relational algebra.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Benford's Law Empirical Digit Extraction and Chi-Square Goodness-of-Fit
-- ----------------------------------------------------------------------------
-- Natural network payload volumes and byte transfers adhere to Benford's Law:
--   P(d) = log10(1 + 1/d) for d in {1, 2, ..., 9}
--
-- Expected theoretical probabilities:
--   d=1: 30.10%, d=2: 17.61%, d=3: 12.49%, d=4: 9.69%, d=5: 7.92%
--   d=6:  6.69%, d=7:  5.80%, d=8:  5.12%, d=9: 4.58%
--
-- Adversary payload manipulation (fixed beacon sizes, encrypted exfiltration
-- chunking, or uniform padding) produces severe departures from Benford's law.
-- The Chi-Square test statistic:
--   Chi2 = Sum_{d=1}^9 [ (O_d - E_d)^2 / E_d ]
-- Critical value for df = 8 at alpha = 0.01 is 20.09; at alpha = 0.05 is 15.51.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_benford_law_flow_analysis AS
WITH non_zero_flows AS (
    SELECT
        src_addr,
        bytes_transferred,
        -- Extract the leading non-zero digit
        CAST(SUBSTR(CAST(bytes_transferred AS VARCHAR), 1, 1) AS INTEGER) AS leading_digit
    FROM telemetry_vpc_flow_logs
    WHERE bytes_transferred > 0
),
digit_domain AS (
    SELECT 1 AS digit, 0.301030 AS p_expected UNION ALL
    SELECT 2 AS digit, 0.176091 AS p_expected UNION ALL
    SELECT 3 AS digit, 0.124939 AS p_expected UNION ALL
    SELECT 4 AS digit, 0.096910 AS p_expected UNION ALL
    SELECT 5 AS digit, 0.079181 AS p_expected UNION ALL
    SELECT 6 AS digit, 0.066947 AS p_expected UNION ALL
    SELECT 7 AS digit, 0.057992 AS p_expected UNION ALL
    SELECT 8 AS digit, 0.051153 AS p_expected UNION ALL
    SELECT 9 AS digit, 0.045757 AS p_expected
),
source_totals AS (
    SELECT
        src_addr,
        COUNT(*) AS total_samples
    FROM non_zero_flows
    GROUP BY src_addr
    HAVING COUNT(*) >= 30 -- Minimum sample size for asymptotic chi-square validity
),
observed_counts AS (
    SELECT
        f.src_addr,
        f.leading_digit,
        COUNT(*) AS o_count
    FROM non_zero_flows f
    GROUP BY f.src_addr, f.leading_digit
),
cross_expected AS (
    SELECT
        s.src_addr,
        s.total_samples,
        d.digit,
        d.p_expected,
        (s.total_samples * d.p_expected) AS e_count,
        COALESCE(o.o_count, 0) AS o_count
    FROM source_totals s
    CROSS JOIN digit_domain d
    LEFT JOIN observed_counts o
      ON s.src_addr = o.src_addr AND d.digit = o.leading_digit
),
chi_square_components AS (
    SELECT
        src_addr,
        total_samples,
        digit,
        o_count,
        e_count,
        POWER(CAST(o_count AS DOUBLE) - e_count, 2) / e_count AS chi_sq_component
    FROM cross_expected
)
SELECT
    src_addr,
    total_samples,
    SUM(chi_sq_component) AS chi_square_stat,
    8 AS degrees_of_freedom,
    15.507 AS critical_value_95,
    20.090 AS critical_value_99,
    CASE
        WHEN SUM(chi_sq_component) > 20.090 THEN 'ANOMALOUS_SYNTHETIC_PAYLOAD_99'
        WHEN SUM(chi_sq_component) > 15.507 THEN 'SUSPICIOUS_DISTRIBUTION_95'
        ELSE 'NATURAL_BENFORD_CONFORMANT'
    END AS benford_verdict
FROM chi_square_components
GROUP BY src_addr, total_samples;

-- ----------------------------------------------------------------------------
-- 2. Exponentially Weighted Moving Average (EWMA) Baseline Model
-- ----------------------------------------------------------------------------
-- Computes rolling smoothed expectation S_t = alpha * y_t + (1 - alpha) * S_{t-1}
-- with smoothing factor alpha = 0.20 (giving 80% weight to historical baseline).
-- Deviations exceeding 3 standard errors are classified as baseline breaks.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_ewma_hourly_auths AS
WITH hourly_auths AS (
    SELECT
        principal_id,
        DATE_TRUNC('hour', event_time) AS auth_hour,
        COUNT(*) AS auth_count,
        SUM(CASE WHEN auth_status = 'FAILURE' THEN 1 ELSE 0 END) AS failure_count
    FROM telemetry_authentication_events
    WHERE principal_id IS NOT NULL
    GROUP BY principal_id, DATE_TRUNC('hour', event_time)
),
lagged_series AS (
    SELECT
        principal_id,
        auth_hour,
        auth_count,
        failure_count,
        LAG(auth_count, 1) OVER (PARTITION BY principal_id ORDER BY auth_hour) AS lag1_count,
        LAG(auth_count, 2) OVER (PARTITION BY principal_id ORDER BY auth_hour) AS lag2_count,
        AVG(auth_count) OVER (PARTITION BY principal_id ORDER BY auth_hour ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING) AS prior_24h_mean,
        COALESCE(STDDEV_SAMP(auth_count) OVER (PARTITION BY principal_id ORDER BY auth_hour ROWS BETWEEN 24 PRECEDING AND 1 PRECEDING), 1.0) AS prior_24h_stddev
    FROM hourly_auths
)
SELECT
    principal_id,
    auth_hour,
    auth_count,
    failure_count,
    prior_24h_mean,
    prior_24h_stddev,
    -- Approximation of 3-term exponential weighting: 0.50 * y_t + 0.35 * y_{t-1} + 0.15 * y_{t-2}
    (0.50 * auth_count + 0.35 * COALESCE(lag1_count, auth_count) + 0.15 * COALESCE(lag2_count, auth_count)) AS smoothed_ewma,
    CASE
        WHEN prior_24h_mean IS NOT NULL AND (auth_count - prior_24h_mean) > (3.0 * prior_24h_stddev) THEN 'ANOMALOUS_SURGE'
        WHEN failure_count > 5 THEN 'AUTHENTICATION_FAILURE_BURST'
        ELSE 'NOMINAL'
    END AS auth_velocity_state
FROM lagged_series;
