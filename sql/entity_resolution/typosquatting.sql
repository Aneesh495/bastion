-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/entity_resolution/typosquatting.sql
-- Description: Domain and username typosquatting detection, homoglyph identification,
--              and corporate brand impersonation analysis in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Canonical Protected Domain Roster
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_protected_domain_roster AS
-- Corporate primary domain
SELECT
    org_id,
    root_domain AS protected_domain,
    'CORPORATE_ROOT_DOMAIN' AS domain_category
FROM core_organizations

UNION ALL

-- Critical infrastructure & SaaS dependencies
SELECT 'SYSTEM' AS org_id, 'okta.com' AS protected_domain, 'IDENTITY_PROVIDER' AS domain_category UNION ALL
SELECT 'SYSTEM' AS org_id, 'microsoft.com' AS protected_domain, 'ENTERPRISE_SUITE' AS domain_category UNION ALL
SELECT 'SYSTEM' AS org_id, 'github.com' AS protected_domain, 'CODE_REPOSITORY' AS domain_category UNION ALL
SELECT 'SYSTEM' AS org_id, 'aws.amazon.com' AS protected_domain, 'CLOUD_INFRASTRUCTURE' AS domain_category UNION ALL
SELECT 'SYSTEM' AS org_id, 'slack.com' AS protected_domain, 'COLLABORATION_PLATFORM' AS domain_category;

-- ----------------------------------------------------------------------------
-- 2. Typosquatted Domain Detection via Edit Distance and Token Overlap
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_detected_domain_typosquats AS
WITH candidate_queries AS (
    SELECT DISTINCT
        q.query_name,
        LOWER(TRIM(q.query_name)) AS clean_query,
        q.asset_id,
        q.query_time
    FROM telemetry_dns_queries q
),
cross_evaluation AS (
    SELECT
        c.query_name,
        c.clean_query,
        c.asset_id,
        c.query_time,
        p.protected_domain,
        p.domain_category,
        LENGTH(c.clean_query) AS query_len,
        LENGTH(p.protected_domain) AS target_len,
        ABS(LENGTH(c.clean_query) - LENGTH(p.protected_domain)) AS len_diff
    FROM candidate_queries c
    CROSS JOIN v_protected_domain_roster p
    WHERE c.clean_query <> p.protected_domain -- Exclude genuine domain visits
      AND ABS(LENGTH(c.clean_query) - LENGTH(p.protected_domain)) <= 3
)
SELECT
    query_name,
    asset_id,
    query_time,
    protected_domain,
    domain_category,
    len_diff,
    -- Heuristic edit distance calculation
    CASE
        WHEN clean_query LIKE '%' || protected_domain || '%' AND clean_query <> protected_domain THEN 'SUBDOMAIN_DECEPTION_PHISHING'
        WHEN SUBSTR(clean_query, 1, 4) = SUBSTR(protected_domain, 1, 4) AND len_diff <= 1 THEN 'CLOSE_PREFIX_TYPOSQUAT'
        WHEN clean_query LIKE '%.%' AND SUBSTR(clean_query, -4) = SUBSTR(protected_domain, -4) AND len_diff <= 2 THEN 'CLOSE_SUFFIX_TYPOSQUAT'
        ELSE 'DISTANT_MATCH'
    END AS typosquat_technique,
    CASE
        WHEN clean_query LIKE '%' || protected_domain || '%' AND clean_query <> protected_domain THEN 96.0
        WHEN SUBSTR(clean_query, 1, 4) = SUBSTR(protected_domain, 1, 4) AND len_diff <= 1 THEN 90.0
        ELSE 65.0
    END AS suspicion_score
FROM cross_evaluation
WHERE (
    clean_query LIKE '%' || protected_domain || '%' OR
    (SUBSTR(clean_query, 1, 4) = SUBSTR(protected_domain, 1, 4) AND len_diff <= 1)
);
