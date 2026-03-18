-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/05_analytics.sql
-- Description: Statistical feature stores, rolling window baselines, Welford
--              variance state, CUSUM control accumulators, and anomaly state tables.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Entity Behavioral Profiling Baselines
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS analytics_principal_baselines (
    baseline_id         VARCHAR(64) PRIMARY KEY,
    principal_id        VARCHAR(64) NOT NULL REFERENCES core_identity_principals(principal_id),
    baseline_window_days INTEGER NOT NULL DEFAULT 30,
    mean_daily_logins   NUMERIC(8,2) NOT NULL DEFAULT 1.00,
    stddev_daily_logins NUMERIC(8,2) NOT NULL DEFAULT 0.50,
    typical_hour_mask   BIGINT NOT NULL DEFAULT 16777215, -- 24-bit bitmask representing standard active UTC hours
    primary_country     VARCHAR(8) NOT NULL DEFAULT 'US',
    allowed_countries   TEXT NOT NULL DEFAULT 'US,CA',     -- Comma-separated ISO country codes
    p95_session_duration INTEGER NOT NULL DEFAULT 28800,   -- In seconds (8 hours)
    last_computed_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_principal_baseline UNIQUE (principal_id)
);

CREATE TABLE IF NOT EXISTS analytics_host_egress_baselines (
    baseline_id         VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    hour_of_day         INTEGER NOT NULL CHECK (hour_of_day BETWEEN 0 AND 23),
    day_of_week         INTEGER NOT NULL CHECK (day_of_week BETWEEN 0 AND 6),
    welford_count       BIGINT NOT NULL DEFAULT 0,
    welford_mean_bytes  NUMERIC(14,2) NOT NULL DEFAULT 0.00,
    welford_m2_bytes    NUMERIC(18,2) NOT NULL DEFAULT 0.00,
    stddev_bytes        NUMERIC(14,2) NOT NULL DEFAULT 0.00,
    p95_bytes_out       BIGINT NOT NULL DEFAULT 0,
    p99_bytes_out       BIGINT NOT NULL DEFAULT 0,
    last_computed_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_host_temporal_baseline UNIQUE (asset_id, hour_of_day, day_of_week)
);

CREATE TABLE IF NOT EXISTS analytics_dns_entropy_baselines (
    baseline_id         VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    sample_count        BIGINT NOT NULL DEFAULT 0,
    mean_entropy        NUMERIC(6,4) NOT NULL DEFAULT 2.5000,
    stddev_entropy      NUMERIC(6,4) NOT NULL DEFAULT 0.4000,
    max_observed_entropy NUMERIC(6,4) NOT NULL DEFAULT 3.8000,
    last_computed_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_host_dns_baseline UNIQUE (asset_id)
);

-- ----------------------------------------------------------------------------
-- 2. Streaming State Accumulators and Rolling Window Caches
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS analytics_rolling_window_aggregates (
    aggregate_id        VARCHAR(64) PRIMARY KEY,
    entity_type         VARCHAR(32) NOT NULL CHECK (entity_type IN ('PRINCIPAL', 'ASSET', 'SUBNET', 'SRC_IP')),
    entity_id           VARCHAR(64) NOT NULL,
    window_interval     VARCHAR(16) NOT NULL CHECK (window_interval IN ('5M', '1H', '24H', '7D')),
    window_start        TIMESTAMP NOT NULL,
    window_end          TIMESTAMP NOT NULL,
    event_count         BIGINT NOT NULL DEFAULT 0,
    sum_bytes           BIGINT NOT NULL DEFAULT 0,
    unique_dst_ips      INTEGER NOT NULL DEFAULT 0,
    unique_dst_ports    INTEGER NOT NULL DEFAULT 0,
    reject_count        INTEGER NOT NULL DEFAULT 0,
    welford_mean        NUMERIC(14,2) NOT NULL DEFAULT 0.00,
    welford_m2          NUMERIC(18,2) NOT NULL DEFAULT 0.00,
    cusum_positive      NUMERIC(12,2) NOT NULL DEFAULT 0.00,
    cusum_negative      NUMERIC(12,2) NOT NULL DEFAULT 0.00,
    last_updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_window_span CHECK (window_end >= window_start)
);

-- ----------------------------------------------------------------------------
-- 3. Materialized Anomaly Detections
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS analytics_detected_anomalies (
    anomaly_id          VARCHAR(64) PRIMARY KEY,
    entity_type         VARCHAR(32) NOT NULL,
    entity_id           VARCHAR(64) NOT NULL,
    metric_name         VARCHAR(64) NOT NULL,
    anomaly_type        VARCHAR(32) NOT NULL CHECK (anomaly_type IN (
                            'Z_SCORE_SPIKE', 'CUSUM_MEAN_SHIFT', 'MAD_OUTLIER',
                            'BENFORD_CHI_SQUARE', 'BEACONING_AUTOCORRELATION',
                            'IMPOSSIBLE_TRAVEL_VELOCITY', 'HIGH_ENTROPY_DGA'
                        )),
    observed_value      NUMERIC(16,4) NOT NULL,
    expected_value      NUMERIC(16,4) NOT NULL,
    z_score             NUMERIC(8,2),
    confidence_pct      NUMERIC(5,2) NOT NULL CHECK (confidence_pct BETWEEN 0.0 AND 100.0),
    detected_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    window_start        TIMESTAMP NOT NULL,
    window_end          TIMESTAMP NOT NULL,
    metadata_json       TEXT
);

CREATE INDEX IF NOT EXISTS idx_anomalies_entity ON analytics_detected_anomalies(entity_type, entity_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_anomalies_type ON analytics_detected_anomalies(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_rolling_entity_window ON analytics_rolling_window_aggregates(entity_type, entity_id, window_interval);
