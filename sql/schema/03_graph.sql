-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/03_graph.sql
-- Description: Directed graph topology, temporal edge intervals, adjacency structures,
--              and transitive reachability cache for zero-trust graph traversal.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Canonical Graph Nodes (Entities in Zero-Trust Topology)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id             VARCHAR(64) PRIMARY KEY,
    node_type           VARCHAR(32) NOT NULL CHECK (node_type IN (
                            'PRINCIPAL', 'ROLE', 'GROUP', 'COMPUTE_ASSET',
                            'SUBNET', 'VIRTUAL_NETWORK', 'STORAGE_BUCKET',
                            'DATABASE', 'INTERNET_GATEWAY', 'EXTERNAL_IP',
                            'SECURITY_GROUP', 'ORGANIZATIONAL_UNIT'
                        )),
    canonical_arn       VARCHAR(512) NOT NULL UNIQUE,
    display_name        VARCHAR(255) NOT NULL,
    account_id          VARCHAR(64) REFERENCES core_cloud_accounts(account_id),
    criticality_tier    INTEGER NOT NULL DEFAULT 3 CHECK (criticality_tier BETWEEN 1 AND 5), -- 1=Crown Jewel, 5=Ephemeral
    is_compromised      BOOLEAN NOT NULL DEFAULT FALSE,
    is_quarantined      BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. Directed Temporal Graph Edges (Relationships and Reachability)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id             VARCHAR(64) PRIMARY KEY,
    source_node_id      VARCHAR(64) NOT NULL REFERENCES graph_nodes(node_id),
    target_node_id      VARCHAR(64) NOT NULL REFERENCES graph_nodes(node_id),
    edge_type           VARCHAR(32) NOT NULL CHECK (edge_type IN (
                            'MEMBER_OF',            -- Principal in Group
                            'CAN_ASSUME_ROLE',      -- Principal/Role can assume Role
                            'HAS_PERMISSION_ON',    -- Principal/Role has access to Resource
                            'NETWORK_INGRESS',      -- Network traffic path allowed
                            'NETWORK_EGRESS',       -- Outbound network route allowed
                            'CONTAINS_ASSET',       -- Subnet contains Compute Asset
                            'ATTACHED_TO',          -- Policy attached to Role/User
                            'PEERED_WITH',          -- VNet Peering connection
                            'TRUSTS_ACCOUNT'        -- Cross-account trust relationship
                        )),
    edge_weight         NUMERIC(8,4) NOT NULL DEFAULT 1.0000 CHECK (edge_weight >= 0.0),
    protocol            VARCHAR(16) DEFAULT 'ANY',
    port_range          VARCHAR(32) DEFAULT 'ALL',
    action_granted      VARCHAR(128),               -- e.g. iam:PassRole, s3:GetObject
    valid_from          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    valid_to            TIMESTAMP,                  -- NULL indicates indefinitely valid
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_edge_nodes_differ CHECK (source_node_id <> target_node_id)
);

-- ----------------------------------------------------------------------------
-- 3. Transitive Reachability and Path Cache
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS graph_reachability_cache (
    cache_id            VARCHAR(64) PRIMARY KEY,
    source_node_id      VARCHAR(64) NOT NULL REFERENCES graph_nodes(node_id),
    target_node_id      VARCHAR(64) NOT NULL REFERENCES graph_nodes(node_id),
    hop_count           INTEGER NOT NULL CHECK (hop_count >= 1),
    min_weight_path     NUMERIC(10,4) NOT NULL,
    traversal_path      TEXT NOT NULL,              -- JSON or delimited array of node IDs
    has_privilege_escalation BOOLEAN NOT NULL DEFAULT FALSE,
    computed_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP NOT NULL,
    CONSTRAINT uq_reachability_pair UNIQUE (source_node_id, target_node_id)
);

-- ----------------------------------------------------------------------------
-- 4. Dynamic Projection Views
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_active_graph_edges AS
SELECT
    e.edge_id,
    e.source_node_id,
    src.display_name AS source_name,
    src.node_type AS source_type,
    e.target_node_id,
    tgt.display_name AS target_name,
    tgt.node_type AS target_type,
    e.edge_type,
    e.edge_weight,
    e.action_granted,
    e.protocol,
    e.port_range,
    e.valid_from,
    e.valid_to
FROM graph_edges e
JOIN graph_nodes src ON e.source_node_id = src.node_id
JOIN graph_nodes tgt ON e.target_node_id = tgt.node_id
WHERE e.is_active = TRUE
  AND src.is_active = TRUE
  AND tgt.is_active = TRUE
  AND (e.valid_to IS NULL OR e.valid_to > CURRENT_TIMESTAMP);

-- Spatial and relational indexing for graph traversal
CREATE INDEX IF NOT EXISTS idx_edges_src_tgt ON graph_edges(source_node_id, target_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_tgt_src ON graph_edges(target_node_id, source_node_id);
CREATE INDEX IF NOT EXISTS idx_edges_type_active ON graph_edges(edge_type, is_active);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_nodes_arn ON graph_nodes(canonical_arn);
