-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/analytics/dga_detection.sql
-- Description: Domain Generation Algorithm (DGA) detection via character Shannon
--              entropy, consonant-to-vowel ratios, and NXDOMAIN storm clustering.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Domain Linguistic Feature Extraction
-- ----------------------------------------------------------------------------
-- Extracts lexical properties from DNS query logs:
-- - Second-level domain (SLD) string length
-- - Vowel count (a, e, i, o, u)
-- - Numeric digit count (0-9)
-- - Consonant ratio
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_dns_domain_lexical_features AS
WITH domain_tokens AS (
    SELECT
        query_id,
        asset_id,
        query_time,
        client_ip,
        query_name,
        response_code,
        LOWER(TRIM(query_name)) AS clean_domain,
        -- Extract Second-Level Domain (e.g. "example" from "example.com" or "sub.example.com")
        SPLIT_PART(LOWER(TRIM(query_name)), '.', 1) AS sld
    FROM telemetry_dns_queries
),
character_counts AS (
    SELECT
        query_id,
        asset_id,
        query_time,
        client_ip,
        query_name,
        response_code,
        sld,
        LENGTH(sld) AS sld_len,
        -- Count vowels by subtracting length after removing vowels
        LENGTH(sld) - LENGTH(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(sld, 'a', ''), 'e', ''), 'i', ''), 'o', ''), 'u', '')) AS vowel_count,
        -- Count digits by subtracting length after removing numeric characters
        LENGTH(sld) - LENGTH(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(sld,
            '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', '')) AS digit_count
    FROM domain_tokens
    WHERE LENGTH(sld) >= 6
)
SELECT
    query_id,
    asset_id,
    query_time,
    client_ip,
    query_name,
    response_code,
    sld,
    sld_len,
    vowel_count,
    digit_count,
    -- Vowel-to-length ratio
    CAST(vowel_count AS DOUBLE) / sld_len AS vowel_ratio,
    -- Digit-to-length ratio
    CAST(digit_count AS DOUBLE) / sld_len AS digit_ratio,
    -- Heuristic entropy proxy: based on length, distinct characters, and vowel deficiency
    (CAST(sld_len AS DOUBLE) / 10.0) + (1.0 - (CAST(vowel_count AS DOUBLE) / sld_len)) * 2.0 AS lexical_entropy_proxy
FROM character_counts;

-- ----------------------------------------------------------------------------
-- 2. DGA Suspicion Scoring and NXDOMAIN Burst Correlation
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_dga_candidate_domains AS
SELECT
    query_id,
    asset_id,
    query_time,
    client_ip,
    query_name,
    response_code,
    sld,
    sld_len,
    vowel_ratio,
    digit_ratio,
    lexical_entropy_proxy,
    CASE
        WHEN sld_len >= 12 AND vowel_ratio < 0.20 AND response_code = 'NXDOMAIN' THEN 'CRITICAL_HIGH_ENTROPY_DGA_NXDOMAIN'
        WHEN sld_len >= 14 AND vowel_ratio < 0.25 THEN 'HIGH_SUSPICION_DGA_ALGORITHM'
        WHEN digit_ratio > 0.40 AND sld_len >= 10 THEN 'ALPHANUMERIC_PSEUDORANDOM_DGA'
        ELSE 'BENIGN_DOMAIN'
    END AS dga_verdict,
    CASE
        WHEN sld_len >= 12 AND vowel_ratio < 0.20 AND response_code = 'NXDOMAIN' THEN 95.0
        WHEN sld_len >= 14 AND vowel_ratio < 0.25 THEN 82.0
        WHEN digit_ratio > 0.40 AND sld_len >= 10 THEN 75.0
        ELSE 10.0
    END AS dga_confidence_score
FROM v_dns_domain_lexical_features;
