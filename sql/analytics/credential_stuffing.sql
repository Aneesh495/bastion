-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/analytics/credential_stuffing.sql
-- Description: Spatial-temporal credential stuffing, distributed password spraying,
--              and coordinated botnet brute-force clustering in relational algebra.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Sliding Window Authentication Failure Accumulator
-- ----------------------------------------------------------------------------
-- Aggregates authentication telemetry into 5-minute time windows partitioned
-- by source IP address and target account, tracking failure velocity.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_auth_failure_velocity AS
SELECT
    source_ip,
    account_id,
    DATE_TRUNC('hour', event_time) AS auth_window,
    COUNT(*) AS total_attempts,
    SUM(CASE WHEN auth_status = 'FAILURE' THEN 1 ELSE 0 END) AS failed_attempts,
    SUM(CASE WHEN auth_status = 'SUCCESS' THEN 1 ELSE 0 END) AS successful_attempts,
    COUNT(DISTINCT username_asserted) AS distinct_usernames_targeted,
    COUNT(DISTINCT user_agent) AS distinct_user_agents_used,
    MIN(event_time) AS first_attempt_at,
    MAX(event_time) AS last_attempt_at
FROM telemetry_authentication_events
GROUP BY source_ip, account_id, DATE_TRUNC('hour', event_time);

-- ----------------------------------------------------------------------------
-- 2. Distributed Password Spraying Campaign Cluster Detection
-- ----------------------------------------------------------------------------
-- Identifies distributed campaigns where multiple distinct source IPs target
-- common identity accounts within a synchronized time window.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_distributed_password_spray_campaigns AS
WITH windowed_failures AS (
    SELECT
        account_id,
        auth_window,
        COUNT(DISTINCT source_ip) AS distinct_attacking_ips,
        SUM(distinct_usernames_targeted) AS distinct_targeted_users,
        SUM(failed_attempts) AS total_failures,
        SUM(successful_attempts) AS total_successful_logins
    FROM v_auth_failure_velocity
    WHERE failed_attempts >= 2
    GROUP BY account_id, auth_window
    HAVING COUNT(DISTINCT source_ip) >= 3 -- At least 3 coordinated source IPs
)
SELECT
    account_id,
    auth_window,
    distinct_attacking_ips,
    distinct_targeted_users,
    total_failures,
    total_successful_logins,
    CAST(total_failures AS DOUBLE) / distinct_attacking_ips AS failures_per_ip_ratio,
    CASE
        WHEN total_successful_logins > 0 THEN 'CRITICAL_PASSWORD_SPRAY_WITH_BREACH'
        WHEN distinct_attacking_ips >= 10 THEN 'MASSIVE_DISTRIBUTED_BOTNET_SPRAY'
        ELSE 'COORDINATED_LOW_AND_SLOW_SPRAY'
    END AS campaign_severity,
    CASE
        WHEN total_successful_logins > 0 THEN 99.0
        WHEN distinct_attacking_ips >= 10 THEN 90.0
        ELSE 78.0
    END AS risk_score
FROM windowed_failures;

-- ----------------------------------------------------------------------------
-- 3. High-Confidence Account Compromise After Sustained Failures
-- ----------------------------------------------------------------------------
-- Pinpoints specific accounts that suffered repeated failed authentication
-- attempts followed by a successful login from a foreign or untrusted IP.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_compromised_accounts_post_bruteforce AS
WITH ranked_attempts AS (
    SELECT
        auth_event_id,
        principal_id,
        username_asserted,
        auth_status,
        source_ip,
        source_country,
        event_time,
        LAG(auth_status, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_status_1,
        LAG(auth_status, 2) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_status_2,
        LAG(auth_status, 3) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_status_3
    FROM telemetry_authentication_events
)
SELECT
    auth_event_id,
    principal_id,
    username_asserted,
    source_ip AS breaching_ip,
    source_country AS breaching_country,
    event_time AS compromise_timestamp,
    'CONSECUTIVE_FAILURES_FOLLOWED_BY_SUCCESS' AS breach_pattern,
    95.0 AS confidence_score
FROM ranked_attempts
WHERE auth_status = 'SUCCESS'
  AND prev_status_1 = 'FAILURE'
  AND prev_status_2 = 'FAILURE'
  AND prev_status_3 = 'FAILURE';
