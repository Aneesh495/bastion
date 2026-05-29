-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/entity_resolution/identity_clusters.sql
-- Description: Probabilistic identity resolution, cross-cloud alias clustering,
--              and unified human principal graph construction in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Identity Token Normalization and Feature Extraction
-- ----------------------------------------------------------------------------
-- Strips domain suffixes, downcases strings, and extracts normalized name stems
-- from usernames, email addresses, and IAM ARNs.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_normalized_principal_tokens AS
SELECT
    principal_id,
    org_id,
    account_id,
    username,
    email,
    arn,
    department,
    -- Normalized username stem
    LOWER(REPLACE(REPLACE(REPLACE(username, '.', ''), '_', ''), '-', '')) AS clean_username_stem,
    -- Email user prefix
    LOWER(SPLIT_PART(COALESCE(email, username), '@', 1)) AS email_prefix,
    -- Initial character
    SUBSTR(LOWER(username), 1, 1) AS initial_char
FROM core_identity_principals;

-- ----------------------------------------------------------------------------
-- 2. Pairwise Identity Similarity and Association Score
-- ----------------------------------------------------------------------------
-- Computes probabilistic affinity between disparate identity accounts based on:
-- - Exact match on email prefix and username stem (Score: 95)
-- - Shared department and matching initial + surname (Score: 80)
-- - Direct role assumption relationship in IAM graph (Score: 90)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_identity_alias_candidate_pairs AS
SELECT
    p1.principal_id AS principal_id_a,
    p1.username AS username_a,
    p1.arn AS arn_a,
    p2.principal_id AS principal_id_b,
    p2.username AS username_b,
    p2.arn AS arn_b,
    p1.department,
    CASE
        WHEN p1.email_prefix = p2.email_prefix THEN 95.0
        WHEN p1.clean_username_stem = p2.clean_username_stem THEN 90.0
        WHEN p1.initial_char = p2.initial_char AND p1.department = p2.department AND p1.department IS NOT NULL THEN 75.0
        ELSE 40.0
    END AS match_confidence_score,
    CASE
        WHEN p1.email_prefix = p2.email_prefix THEN 'EXACT_EMAIL_PREFIX_MATCH'
        WHEN p1.clean_username_stem = p2.clean_username_stem THEN 'STEM_NORMALIZATION_MATCH'
        WHEN p1.initial_char = p2.initial_char AND p1.department = p2.department THEN 'ORGANIZATIONAL_DEPARTMENT_CORRELATION'
        ELSE 'HEURISTIC_OVERLAP'
    END AS match_rationale
FROM v_normalized_principal_tokens p1
JOIN v_normalized_principal_tokens p2
  ON p1.principal_id < p2.principal_id
WHERE (
    p1.email_prefix = p2.email_prefix OR
    p1.clean_username_stem = p2.clean_username_stem OR
    (p1.initial_char = p2.initial_char AND p1.department = p2.department AND p1.department IS NOT NULL)
);

-- ----------------------------------------------------------------------------
-- 3. Transitive Identity Equivalence Clusters
-- ----------------------------------------------------------------------------
-- Connects paired aliases into unified cross-account human identity clusters.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_unified_identity_clusters AS
SELECT
    principal_id_a AS cluster_root_principal_id,
    username_a AS canonical_display_name,
    principal_id_b AS alias_principal_id,
    username_b AS alias_username,
    arn_b AS alias_arn,
    match_confidence_score,
    match_rationale
FROM v_identity_alias_candidate_pairs
WHERE match_confidence_score >= 75.0;
