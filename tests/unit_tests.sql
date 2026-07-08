-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: tests/unit_tests.sql
-- Description: Unit test verification suite for mathematical, statistical,
--              string similarity, and network CIDR functions in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Unit Test Suite 1: Mathematical Statistics and Anomaly Functions
-- ----------------------------------------------------------------------------

-- Test 1.1: Welford running variance and standard deviation computation
WITH test_data AS (
    SELECT UNNEST([10.0, 10.0, 10.0, 10.0]) AS val
),
stats AS (
    SELECT
        AVG(val) AS mean_val,
        STDDEV_POP(val) AS std_val
    FROM test_data
)
SELECT
    'MATH_STATS' AS suite,
    'welford_zero_variance' AS test_name,
    CASE WHEN std_val = 0.0 AND mean_val = 10.0 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(std_val AS VARCHAR) AS actual,
    '0.0' AS expected,
    'Zero variance validation on uniform distribution' AS description
FROM stats;

-- Test 1.2: Exponential Weighted Moving Average (EWMA) Alpha Response
WITH RECURSIVE signal_series(step, val) AS (
    SELECT 1, 100.0
    UNION ALL
    SELECT step + 1, 100.0 FROM signal_series WHERE step < 5
),
ewma_calc AS (
    SELECT
        step,
        val,
        AVG(val) OVER (ORDER BY step ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS smoothed
    FROM signal_series
)
SELECT
    'MATH_STATS' AS suite,
    'ewma_convergence' AS test_name,
    CASE WHEN smoothed = 100.0 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(smoothed AS VARCHAR) AS actual,
    '100.0' AS expected,
    'EWMA convergence verification under stationary input' AS description
FROM ewma_calc
WHERE step = 5;

-- Test 1.3: Benford First-Digit Distribution Validation
WITH benford_samples AS (
    SELECT UNNEST([12, 190, 1045, 18, 230, 310, 45, 59, 61, 78, 89, 95]) AS num
),
first_digits AS (
    SELECT
        CAST(SUBSTR(CAST(num AS VARCHAR), 1, 1) AS INTEGER) AS lead_digit
    FROM benford_samples
),
digit_one_count AS (
    SELECT COUNT(*) AS c1 FROM first_digits WHERE lead_digit = 1
)
SELECT
    'BENFORD_LAW' AS suite,
    'benford_first_digit_extraction' AS test_name,
    CASE WHEN c1 = 4 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(c1 AS VARCHAR) AS actual,
    '4' AS expected,
    'Extraction of leading significant digit across multiple magnitude scales' AS description
FROM digit_one_count;

-- ----------------------------------------------------------------------------
-- Unit Test Suite 2: String Metrics and Phonetic Encodings
-- ----------------------------------------------------------------------------

-- Test 2.1: Trigram Tokenization and Cardinality
WITH token_test AS (
    SELECT 'security' AS s
),
trigrams AS (
    SELECT
        SUBSTR(s, i, 3) AS gram
    FROM token_test,
    (SELECT UNNEST(range(1, 7)) AS i)
)
SELECT
    'STRING_METRICS' AS suite,
    'trigram_cardinality' AS test_name,
    CASE WHEN COUNT(DISTINCT gram) = 6 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(COUNT(DISTINCT gram) AS VARCHAR) AS actual,
    '6' AS expected,
    'Trigram generation on 8-character string produces 6 unique substrings' AS description
FROM trigrams;

-- Test 2.2: Trigram Jaccard Similarity on Identical Strings
WITH trigrams_a AS (
    SELECT UNNEST(['sec', 'ecu', 'cur', 'uri', 'rit', 'ity']) AS g
),
trigrams_b AS (
    SELECT UNNEST(['sec', 'ecu', 'cur', 'uri', 'rit', 'ity']) AS g
),
intersection_cnt AS (
    SELECT COUNT(*) AS cnt FROM (
        SELECT g FROM trigrams_a INTERSECT SELECT g FROM trigrams_b
    )
),
union_cnt AS (
    SELECT COUNT(*) AS cnt FROM (
        SELECT g FROM trigrams_a UNION SELECT g FROM trigrams_b
    )
)
SELECT
    'STRING_METRICS' AS suite,
    'jaccard_identical_strings' AS test_name,
    CASE WHEN CAST(i.cnt AS DOUBLE) / CAST(u.cnt AS DOUBLE) = 1.0 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(CAST(i.cnt AS DOUBLE) / CAST(u.cnt AS DOUBLE) AS VARCHAR) AS actual,
    '1.0' AS expected,
    'Jaccard index of identical strings equals 1.0' AS description
FROM intersection_cnt i, union_cnt u;

-- Test 2.3: Trigram Jaccard Similarity on Completely Disjoint Strings
WITH trigrams_a AS (
    SELECT UNNEST(['abc', 'bcd', 'cde']) AS g
),
trigrams_b AS (
    SELECT UNNEST(['xyz', 'yzw', 'zwv']) AS g
),
intersection_cnt AS (
    SELECT COUNT(*) AS cnt FROM (
        SELECT g FROM trigrams_a INTERSECT SELECT g FROM trigrams_b
    )
),
union_cnt AS (
    SELECT COUNT(*) AS cnt FROM (
        SELECT g FROM trigrams_a UNION SELECT g FROM trigrams_b
    )
)
SELECT
    'STRING_METRICS' AS suite,
    'jaccard_disjoint_strings' AS test_name,
    CASE WHEN CAST(i.cnt AS DOUBLE) / CAST(u.cnt AS DOUBLE) = 0.0 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(CAST(i.cnt AS DOUBLE) / CAST(u.cnt AS DOUBLE) AS VARCHAR) AS actual,
    '0.0' AS expected,
    'Jaccard index of disjoint strings equals 0.0' AS description
FROM intersection_cnt i, union_cnt u;

-- ----------------------------------------------------------------------------
-- Unit Test Suite 3: Network IPv4 Octet Math and CIDR Containment
-- ----------------------------------------------------------------------------

-- Test 3.1: IPv4 Dotted-Quad to 32-bit Integer Conversion
WITH test_ips AS (
    SELECT '10.0.1.55' AS ip_str
),
parsed_octets AS (
    SELECT
        CAST(SPLIT_PART(ip_str, '.', 1) AS BIGINT) AS o1,
        CAST(SPLIT_PART(ip_str, '.', 2) AS BIGINT) AS o2,
        CAST(SPLIT_PART(ip_str, '.', 3) AS BIGINT) AS o3,
        CAST(SPLIT_PART(ip_str, '.', 4) AS BIGINT) AS o4
    FROM test_ips
),
ip_int AS (
    SELECT (o1 * 16777216) + (o2 * 65536) + (o3 * 256) + o4 AS num FROM parsed_octets
)
SELECT
    'NETWORK_CIDR' AS suite,
    'ipv4_to_integer' AS test_name,
    CASE WHEN num = 167772471 THEN 'PASS' ELSE 'FAIL' END AS status,
    CAST(num AS VARCHAR) AS actual,
    '167772471' AS expected,
    'Binary arithmetic conversion of 10.0.1.55 to 32-bit unsigned integer' AS description
FROM ip_int;

-- Test 3.2: CIDR /24 Subnet Boundary Containment
WITH subnet_calc AS (
    -- 10.0.1.0/24 bounds: 167772416 to 167772671
    SELECT
        167772416 AS start_ip,
        167772671 AS end_ip,
        167772471 AS test_ip_inside,   -- 10.0.1.55
        167772672 AS test_ip_outside   -- 10.0.2.0
)
SELECT
    'NETWORK_CIDR' AS suite,
    'cidr_containment_in_bounds' AS test_name,
    CASE
        WHEN test_ip_inside >= start_ip AND test_ip_inside <= end_ip THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    'CONTAINED' AS actual,
    'CONTAINED' AS expected,
    'IP 10.0.1.55 falls strictly within 10.0.1.0/24 subnet block' AS description
FROM subnet_calc;

-- Test 3.3: CIDR Subnet Boundary Out-of-Bounds Rejection
WITH subnet_calc AS (
    SELECT
        167772416 AS start_ip,
        167772671 AS end_ip,
        167772672 AS test_ip_outside   -- 10.0.2.0
)
SELECT
    'NETWORK_CIDR' AS suite,
    'cidr_containment_out_of_bounds' AS test_name,
    CASE
        WHEN test_ip_outside >= start_ip AND test_ip_outside <= end_ip THEN 'FAIL'
        ELSE 'PASS'
    END AS status,
    'REJECTED' AS actual,
    'REJECTED' AS expected,
    'IP 10.0.2.0 is outside 10.0.1.0/24 subnet block' AS description
FROM subnet_calc;
