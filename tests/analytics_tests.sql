-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: tests/analytics_tests.sql
-- Description: Verification test suite for statistical anomaly models:
--              C2 periodic beaconing, impossible travel velocity, asymmetric
--              egress exfiltration, DGA entropy, distributed password spray,
--              domain typosquatting, and probabilistic identity clustering.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 1: Command & Control Periodic Beaconing
-- ----------------------------------------------------------------------------

-- Test 1.1: Verification of Low-Jitter Periodic Flow Detection
SELECT
    'ANALYTICS_BEACON' AS suite,
    'c2_beaconing_detected' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Statistical beaconing model identifies low-jitter periodic communications' AS description
FROM v_c2_beaconing_candidates
WHERE coefficient_of_variation <= 0.20
  AND beacon_confidence_score >= 80.0;

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 2: Impossible Geodesic Travel Velocity
-- ----------------------------------------------------------------------------

-- Test 2.1: Supersonic Velocity Detection Across Geographic Logins
SELECT
    'ANALYTICS_GEO' AS suite,
    'impossible_travel_detected' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Haversine great-circle velocity identifies physically impossible transit' AS description
FROM v_impossible_travel_violations
WHERE calculated_velocity_kmh >= 1000.0;

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 3: Asymmetric Data Egress Exfiltration
-- ----------------------------------------------------------------------------

-- Test 3.1: Massive Outbound Data Volume Anomaly Detection
SELECT
    'ANALYTICS_EXFIL' AS suite,
    'asymmetric_egress_detected' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Network telemetry model detects massive outbound byte transfers' AS description
FROM v_asymmetric_egress_flows
WHERE total_egress_bytes >= 1000000000;

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 4: Domain Generation Algorithm (DGA) Entropy
-- ----------------------------------------------------------------------------

-- Test 4.1: High Shannon Lexical Entropy Domain Detection
SELECT
    'ANALYTICS_DGA' AS suite,
    'dga_domains_detected' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Lexical feature extraction flags synthetic algorithmically generated domains' AS description
FROM v_dga_candidate_domains
WHERE dga_confidence_score >= 80.0;

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 5: Distributed Password Spraying
-- ----------------------------------------------------------------------------

-- Test 5.1: Multi-Source Coordinated Authentication Failure Clusters
SELECT
    'ANALYTICS_SPRAY' AS suite,
    'password_spray_campaign_detected' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Windowed clustering identifies distributed authentication brute force campaigns' AS description
FROM v_distributed_password_spray_campaigns
WHERE distinct_attacking_ips >= 3;

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 6: Domain Typosquatting and Brand Deception
-- ----------------------------------------------------------------------------

-- Test 6.1: Phishing and Homoglyph Domain Detection
SELECT
    'ANALYTICS_TYPOSQUAT' AS suite,
    'typosquatted_domains_detected' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Edit distance and prefix metrics identify typosquatted DNS lookups' AS description
FROM v_detected_domain_typosquats
WHERE suspicion_score >= 80.0;

-- ----------------------------------------------------------------------------
-- Analytics Test Suite 7: Probabilistic Identity Resolution
-- ----------------------------------------------------------------------------

-- Test 7.1: Cross-Account Human Principal Alias Clustering
SELECT
    'ANALYTICS_IDENTITY' AS suite,
    'cross_cloud_identity_clusters' AS test_name,
    CASE
        WHEN COUNT(*) >= 1 THEN 'PASS'
        ELSE 'FAIL'
    END AS status,
    CAST(COUNT(*) AS VARCHAR) AS actual,
    '>= 1' AS expected,
    'Stem and token normalization links cross-cloud human identity accounts' AS description
FROM v_unified_identity_clusters
WHERE match_confidence_score >= 80.0;
