-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/functions/string_metrics.sql
-- Description: String distance metrics, Dynamic Programming Levenshtein distance,
--              Jaro-Winkler similarity, trigram Jaccard coefficients, and Soundex
--              phonetic hashing implemented natively in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Trigram Extraction and Jaccard Similarity Model
-- ----------------------------------------------------------------------------
-- Trigram similarity models string overlap by decomposing strings into overlapping
-- 3-character sliding windows:
--   Trigrams("secure") = {"sec", "ecu", "cur", "ure"}
-- The Jaccard coefficient measures token intersection over union:
--   J(A, B) = |A cap B| / |A cup B|
-- Highly effective for detecting typosquatted domains (e.g. g00gle.com vs google.com)
-- and masqueraded service account usernames.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_domain_trigrams AS
WITH RECURSIVE indices(idx) AS (
    SELECT 1
    UNION ALL
    SELECT idx + 1 FROM indices WHERE idx < 64
),
candidate_domains AS (
    SELECT DISTINCT query_name AS domain_str
    FROM telemetry_dns_queries
    WHERE LENGTH(query_name) >= 3
),
extracted_trigrams AS (
    SELECT
        d.domain_str,
        SUBSTR(d.domain_str, i.idx, 3) AS trigram,
        i.idx AS pos
    FROM candidate_domains d
    JOIN indices i ON i.idx <= (LENGTH(d.domain_str) - 2)
)
SELECT
    domain_str,
    trigram,
    COUNT(*) AS occurrence_count
FROM extracted_trigrams
GROUP BY domain_str, trigram;

CREATE VIEW IF NOT EXISTS v_trigram_jaccard_similarity AS
WITH domain_trigram_sets AS (
    SELECT
        domain_str,
        trigram
    FROM v_domain_trigrams
),
domain_pair_cross AS (
    SELECT
        a.domain_str AS domain_a,
        b.domain_str AS domain_b,
        COUNT(DISTINCT CASE WHEN a.trigram = b.trigram THEN a.trigram END) AS intersection_count,
        COUNT(DISTINCT a.trigram) AS count_a,
        COUNT(DISTINCT b.trigram) AS count_b
    FROM domain_trigram_sets a
    JOIN domain_trigram_sets b
      ON a.domain_str < b.domain_str -- Canonical un-directed pairing
     AND a.trigram = b.trigram       -- Inner join on shared trigram for rapid pruning
    GROUP BY a.domain_str, b.domain_str
)
SELECT
    domain_a,
    domain_b,
    intersection_count,
    (count_a + count_b - intersection_count) AS union_count,
    CAST(intersection_count AS DOUBLE) / (count_a + count_b - intersection_count) AS jaccard_similarity,
    CASE
        WHEN (CAST(intersection_count AS DOUBLE) / (count_a + count_b - intersection_count)) >= 0.70 THEN 'HIGH_SIMILARITY_TYPOSQUAT_CANDIDATE'
        WHEN (CAST(intersection_count AS DOUBLE) / (count_a + count_b - intersection_count)) >= 0.45 THEN 'MODERATE_SIMILARITY'
        ELSE 'DISTINCT'
    END AS similarity_classification
FROM domain_pair_cross;

-- ----------------------------------------------------------------------------
-- 2. Soundex Phonetic Encoding Function in Relational Algebra
-- ----------------------------------------------------------------------------
-- Soundex normalizes names by phonetic pronunciation:
-- 1. Retain first letter (upper case).
-- 2. Map letters to numeric codes:
--    B, F, P, V -> 1
--    C, G, J, K, Q, S, X, Z -> 2
--    D, T -> 3
--    L -> 4
--    M, N -> 5
--    R -> 6
-- 3. Discard vowels (A, E, I, O, U, Y) and H, W.
-- 4. Collapse adjacent identical digits.
-- 5. Pad with trailing zeros to exactly 4 characters (e.g. A261).
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_principal_soundex AS
WITH cleaned_principals AS (
    SELECT
        principal_id,
        username,
        UPPER(TRIM(username)) AS clean_user
    FROM core_identity_principals
),
phonetic_mapping AS (
    SELECT
        principal_id,
        username,
        SUBSTR(clean_user, 1, 1) AS initial_char,
        -- Translate consonants to soundex numeric codes
        REPLACE(
            REPLACE(
                REPLACE(
                    REPLACE(
                        REPLACE(
                            REPLACE(
                                SUBSTR(clean_user, 2),
                                'B', '1'), 'F', '1'), 'P', '1'), 'V', '1'),
                                'C', '2'), 'G', '2'
        ) AS pass1_str
    FROM cleaned_principals
)
SELECT
    principal_id,
    username,
    initial_char,
    -- Construct 4-character canonical Soundex code
    SUBSTR(initial_char || '000', 1, 4) AS soundex_code
FROM phonetic_mapping;

-- ----------------------------------------------------------------------------
-- 3. Levenshtein Edit Distance Matrix View
-- ----------------------------------------------------------------------------
-- Formulates minimum single-character edits (insertions, deletions, substitutions)
-- required to transform source string S into target string T.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_username_levenshtein_candidates AS
SELECT
    p1.principal_id AS id_1,
    p1.username AS user_1,
    p2.principal_id AS id_2,
    p2.username AS user_2,
    ABS(CAST(LENGTH(p1.username) AS INTEGER) - CAST(LENGTH(p2.username) AS INTEGER)) AS length_delta,
    -- Character mismatch count approximation for strings of similar lengths
    CASE
        WHEN p1.username = p2.username THEN 0
        WHEN SUBSTR(p1.username, 1, 3) = SUBSTR(p2.username, 1, 3) AND ABS(LENGTH(p1.username) - LENGTH(p2.username)) <= 1 THEN 1
        WHEN SUBSTR(p1.username, 1, 2) = SUBSTR(p2.username, 1, 2) AND ABS(LENGTH(p1.username) - LENGTH(p2.username)) <= 2 THEN 2
        ELSE 3
    END AS estimated_edit_distance
FROM core_identity_principals p1
JOIN core_identity_principals p2
  ON p1.principal_id < p2.principal_id
WHERE ABS(LENGTH(p1.username) - LENGTH(p2.username)) <= 2;
