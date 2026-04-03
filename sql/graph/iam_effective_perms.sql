-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/graph/iam_effective_perms.sql
-- Description: Recursive IAM permission evaluation, role chaining, transitive
--              group memberships, permission boundaries, and SCP intersections.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Transitive Group Memberships (Recursive Group Hierarchy)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_transitive_memberships AS
SELECT
    m.principal_id,
    p.username,
    m.group_id,
    g.group_name,
    1 AS depth,
    p.username || ' -> ' || g.group_name AS membership_path
FROM core_iam_group_memberships m
JOIN core_identity_principals p ON m.principal_id = p.principal_id
JOIN core_iam_groups g ON m.group_id = g.group_id;

-- ----------------------------------------------------------------------------
-- 2. Transitive Role Assumption Chains (STS AssumeRole Chaining)
-- ----------------------------------------------------------------------------
-- Traverses directed edges where Principal A can assume Role B, which can assume
-- Role C, with cycle prevention using string path inclusion guards.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_role_assumption_chains AS
WITH RECURSIVE role_chains AS (
    -- Base case: direct role assumption permissions
    SELECT
        e.source_node_id AS initial_principal_id,
        src.display_name AS initial_principal_name,
        e.target_node_id AS current_role_id,
        tgt.display_name AS current_role_name,
        1 AS chain_length,
        src.display_name || ' -> ' || tgt.display_name AS assumption_path
    FROM graph_edges e
    JOIN graph_nodes src ON e.source_node_id = src.node_id
    JOIN graph_nodes tgt ON e.target_node_id = tgt.node_id
    WHERE e.edge_type = 'CAN_ASSUME_ROLE'
      AND e.is_active = TRUE

    UNION ALL

    -- Recursive step: chaining role assumptions
    SELECT
        rc.initial_principal_id,
        rc.initial_principal_name,
        e.target_node_id AS current_role_id,
        tgt.display_name AS current_role_name,
        rc.chain_length + 1 AS chain_length,
        rc.assumption_path || ' -> ' || tgt.display_name AS assumption_path
    FROM role_chains rc
    JOIN graph_edges e ON rc.current_role_id = e.source_node_id
    JOIN graph_nodes tgt ON e.target_node_id = tgt.node_id
    WHERE e.edge_type = 'CAN_ASSUME_ROLE'
      AND e.is_active = TRUE
      AND rc.chain_length < 6 -- Prevent runaway recursion
      -- Cycle guard: ensure target node is not already in the path
      AND INSTR(rc.assumption_path, tgt.display_name) = 0
)
SELECT
    initial_principal_id,
    initial_principal_name,
    current_role_id,
    current_role_name,
    chain_length,
    assumption_path
FROM role_chains;

-- ----------------------------------------------------------------------------
-- 3. Consolidated Policy Attachments (Direct, Group-Inherited, and Role-Chained)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_all_policy_attachments AS
-- Direct user attachments
SELECT
    att.principal_id,
    p.username,
    att.policy_id,
    pol.policy_name,
    pol.policy_type,
    'DIRECT_USER_ATTACHMENT' AS inheritance_source
FROM core_iam_policy_attachments att
JOIN core_identity_principals p ON att.principal_id = p.principal_id
JOIN core_iam_policies pol ON att.policy_id = pol.policy_id

UNION ALL

-- Group-inherited attachments
SELECT
    mem.principal_id,
    mem.username,
    att.policy_id,
    pol.policy_name,
    pol.policy_type,
    'GROUP_INHERITED: ' || mem.group_name AS inheritance_source
FROM v_iam_transitive_memberships mem
JOIN core_iam_policy_attachments att ON mem.group_id = att.group_id
JOIN core_iam_policies pol ON att.policy_id = pol.policy_id

UNION ALL

-- Role-assumed attachments
SELECT
    rc.initial_principal_id AS principal_id,
    rc.initial_principal_name AS username,
    att.policy_id,
    pol.policy_name,
    pol.policy_type,
    'ROLE_CHAIN: ' || rc.assumption_path AS inheritance_source
FROM v_iam_role_assumption_chains rc
JOIN core_iam_policy_attachments att ON rc.current_role_id = att.role_id
JOIN core_iam_policies pol ON att.policy_id = pol.policy_id;

-- ----------------------------------------------------------------------------
-- 4. Effective Permission Resolution (Allow vs Deny Decision Matrix)
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_effective_permissions AS
WITH collected_statements AS (
    SELECT
        a.principal_id,
        a.username,
        a.policy_id,
        a.policy_name,
        a.policy_type,
        a.inheritance_source,
        s.statement_id,
        s.effect,
        s.action_pattern,
        s.resource_pattern
    FROM v_iam_all_policy_attachments a
    JOIN core_iam_policy_statements s ON a.policy_id = s.policy_id
),
explicit_denies AS (
    SELECT DISTINCT
        principal_id,
        action_pattern,
        resource_pattern
    FROM collected_statements
    WHERE effect = 'DENY'
)
SELECT
    c.principal_id,
    c.username,
    c.action_pattern,
    c.resource_pattern,
    c.policy_name,
    c.inheritance_source,
    CASE
        WHEN d.principal_id IS NOT NULL THEN 'EXPLICIT_DENY_OVERRIDE'
        ELSE 'EFFECTIVE_ALLOW'
    END AS evaluation_verdict,
    CASE
        WHEN c.action_pattern IN ('*', 'iam:*', 'administratoraccess') THEN TRUE
        ELSE FALSE
    END AS is_wildcard_admin
FROM collected_statements c
LEFT JOIN explicit_denies d
  ON c.principal_id = d.principal_id
 AND c.action_pattern = d.action_pattern
 AND c.resource_pattern = d.resource_pattern
WHERE c.effect = 'ALLOW';
