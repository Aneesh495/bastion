-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/seeds/02_cloud_topology.sql
-- Description: Multi-account enterprise cloud topology, virtual networks,
--              DMZ / Application / Data subnets, compute workloads, storage buckets,
--              database clusters, and directed graph topology edges.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Organizations and Cloud Accounts
-- ----------------------------------------------------------------------------

INSERT INTO core_organizations (org_id, org_name, root_domain, compliance_framework, is_active) VALUES
('org-01', 'Bastion Autonomous Technologies', 'bastion-sec.internal', 'SOC2_TYPE_II', TRUE)
ON CONFLICT (org_id) DO NOTHING;

INSERT INTO core_cloud_accounts (account_id, org_id, provider, account_name, environment, region_default, is_isolated) VALUES
('acc-prod-01', 'org-01', 'AWS', 'Bastion-US-East-Production', 'PRODUCTION', 'us-east-1', FALSE),
('acc-sec-01',  'org-01', 'AWS', 'Bastion-Global-Security',   'PRODUCTION', 'us-east-1', TRUE),
('acc-data-01', 'org-01', 'GCP', 'Bastion-Analytics-Lakehouse', 'PRODUCTION', 'us-central1', FALSE),
('acc-dev-01',  'org-01', 'AWS', 'Bastion-Sandbox-Dev',       'DEVELOPMENT', 'us-west-2', FALSE)
ON CONFLICT (account_id) DO NOTHING;

INSERT INTO core_organizational_units (ou_id, org_id, parent_ou_id, ou_name, tier_level) VALUES
('ou-root', 'org-01', NULL, 'Root Organization', 1)
ON CONFLICT (ou_id) DO NOTHING;

INSERT INTO core_organizational_units (ou_id, org_id, parent_ou_id, ou_name, tier_level) VALUES
('ou-prod',    'org-01', 'ou-root', 'Production Workloads', 2),
('ou-sec',     'org-01', 'ou-root', 'Security and Audit', 2),
('ou-sandbox', 'org-01', 'ou-root', 'Developer Sandboxes', 2)
ON CONFLICT (ou_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. Virtual Networks and Subnets
-- ----------------------------------------------------------------------------

INSERT INTO core_virtual_networks (vnet_id, account_id, vnet_name, cidr_block, is_peered, has_internet_gateway) VALUES
('vnet-prod-east', 'acc-prod-01', 'vpc-production-useast1', '10.0.0.0/16', TRUE, TRUE),
('vnet-sec-east',  'acc-sec-01',  'vpc-security-useast1',   '10.200.0.0/16', TRUE, FALSE)
ON CONFLICT (vnet_id) DO NOTHING;

INSERT INTO core_subnets (subnet_id, vnet_id, subnet_name, cidr_block, zone, zone_type, is_public) VALUES
('sub-dmz-01',  'vnet-prod-east', 'subnet-prod-dmz-public-1a',  '10.0.1.0/24',  'us-east-1a', 'DMZ',               TRUE),
('sub-app-01',  'vnet-prod-east', 'subnet-prod-app-private-1a', '10.0.2.0/24',  'us-east-1a', 'APPLICATION',       FALSE),
('sub-data-01', 'vnet-prod-east', 'subnet-prod-data-tier-1a',   '10.0.3.0/24',  'us-east-1a', 'DATA',              FALSE),
('sub-sec-01',  'vnet-sec-east',  'subnet-sec-isolated-1a',     '10.200.1.0/24','us-east-1a', 'SECURITY_ISOLATED', FALSE)
ON CONFLICT (subnet_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. Security Groups and Firewall Invariants
-- ----------------------------------------------------------------------------

INSERT INTO core_security_groups (sg_id, vnet_id, sg_name, description) VALUES
('sg-edge-proxy',  'vnet-prod-east', 'sg-public-reverse-proxy',  'Allows HTTPS ingress from 0.0.0.0/0'),
('sg-app-tier',    'vnet-prod-east', 'sg-internal-microservices', 'Allows TCP 8080 from DMZ only'),
('sg-database',    'vnet-prod-east', 'sg-crown-jewel-database',   'Allows TCP 5432 from App tier only'),
('sg-management',  'vnet-sec-east',  'sg-bastion-ssh-mgmt',       'Allows SSH from secure jump box')
ON CONFLICT (sg_id) DO NOTHING;

INSERT INTO core_security_group_rules (rule_id, sg_id, direction, protocol, from_port, to_port, remote_cidr, remote_sg_id, rule_action, description) VALUES
('sgr-01', 'sg-edge-proxy', 'INBOUND',  'TCP', 443,  443,  '0.0.0.0/0', NULL, 'ALLOW', 'HTTPS public traffic'),
('sgr-02', 'sg-edge-proxy', 'OUTBOUND', 'TCP', 8080, 8080, '10.0.2.0/24', NULL, 'ALLOW', 'Forward to app tier'),
('sgr-03', 'sg-app-tier',   'INBOUND',  'TCP', 8080, 8080, '10.0.1.0/24', NULL, 'ALLOW', 'Ingress from DMZ proxies'),
('sgr-04', 'sg-app-tier',   'OUTBOUND', 'TCP', 5432, 5432, '10.0.3.0/24', NULL, 'ALLOW', 'Egress to database tier'),
('sgr-05', 'sg-database',   'INBOUND',  'TCP', 5432, 5432, '10.0.2.0/24', NULL, 'ALLOW', 'PostgreSQL from app tier')
ON CONFLICT (rule_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. Compute Workloads and Infrastructure Assets
-- ----------------------------------------------------------------------------

INSERT INTO core_compute_assets (
    asset_id, account_id, subnet_id, asset_type, hostname, primary_ip, public_ip,
    mac_address, os_distribution, os_version, is_crown_jewel, criticality_score,
    is_compromised, is_quarantined, state
) VALUES
('ast-edge-01',   'acc-prod-01', 'sub-dmz-01',  'VM_INSTANCE', 'bastion-edge-ingress-01',   '10.0.1.10', '203.0.113.15', '02:42:0a:00:01:0a', 'Debian Linux', '12.5 (bookworm)', FALSE, 65.0, FALSE, FALSE, 'RUNNING'),
('ast-web-01',    'acc-prod-01', 'sub-dmz-01',  'VM_INSTANCE', 'bastion-web-portal-01',     '10.0.1.55', '203.0.113.88', '02:42:0a:00:01:37', 'Ubuntu Linux', '24.04 LTS',          FALSE, 70.0, FALSE, FALSE, 'RUNNING'),
('ast-api-01',    'acc-prod-01', 'sub-app-01',  'CONTAINER_POD', 'prod-core-api-worker-01', '10.0.2.20', NULL,           '02:42:0a:00:02:14', 'Alpine Linux', '3.19',                FALSE, 80.0, FALSE, FALSE, 'RUNNING'),
('ast-settle-01', 'acc-prod-01', 'sub-data-01', 'VM_INSTANCE', 'prod-settlement-engine-01', '10.0.3.15', NULL,           '02:42:0a:00:03:0f', 'RHEL Linux',   '9.3',                 TRUE,  98.0, FALSE, FALSE, 'RUNNING'),
('ast-db-01',     'acc-prod-01', 'sub-data-01', 'VM_INSTANCE', 'prod-primary-db-master',    '10.0.3.50', NULL,           '02:42:0a:00:03:32', 'Rocky Linux',  '9.3',                 TRUE, 100.0, FALSE, FALSE, 'RUNNING'),
('ast-jump-01',   'acc-sec-01',  'sub-sec-01',  'VM_INSTANCE', 'sec-jumpbox-sentinel',      '10.200.1.10', NULL,         '02:42:0a:c8:01:0a', 'Hardened BSD', '14.0-RELEASE',       TRUE,  95.0, FALSE, FALSE, 'RUNNING')
ON CONFLICT (asset_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 5. Data Storage Buckets and Relational Clusters
-- ----------------------------------------------------------------------------

INSERT INTO core_storage_buckets (bucket_id, account_id, bucket_name, data_classification, encryption_algorithm, is_publicly_readable, versioning_enabled, logging_enabled) VALUES
('bkt-pii-01',    'acc-prod-01', 'bastion-prod-restricted-pii-vault',  'RESTRICTED_PII', 'aws:kms', FALSE, TRUE, TRUE),
('bkt-fin-01',    'acc-prod-01', 'bastion-prod-confidential-ledger',   'CONFIDENTIAL',   'aws:kms', FALSE, TRUE, TRUE),
('bkt-public-01', 'acc-prod-01', 'bastion-public-marketing-assets',    'PUBLIC',         'AES256',  TRUE,  TRUE, TRUE)
ON CONFLICT (bucket_id) DO NOTHING;

INSERT INTO core_database_clusters (cluster_id, account_id, subnet_id, engine_name, engine_version, is_public, is_multi_az, is_encrypted_at_rest) VALUES
('db-cluster-01', 'acc-prod-01', 'sub-data-01', 'Aurora PostgreSQL', '16.2', FALSE, TRUE, TRUE)
ON CONFLICT (cluster_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 6. Canonical Graph Nodes and Topology Edges
-- ----------------------------------------------------------------------------

INSERT INTO graph_nodes (node_id, node_type, canonical_arn, display_name, account_id, criticality_tier, is_compromised, is_quarantined, is_active) VALUES
('node-edge-01',   'COMPUTE_ASSET',  'arn:aws:ec2:us-east-1:acc-prod-01:instance/i-edge01',   'bastion-edge-ingress-01',   'acc-prod-01', 3, FALSE, FALSE, TRUE),
('node-web-01',    'COMPUTE_ASSET',  'arn:aws:ec2:us-east-1:acc-prod-01:instance/i-web01',    'bastion-web-portal-01',     'acc-prod-01', 3, FALSE, FALSE, TRUE),
('node-api-01',    'COMPUTE_ASSET',  'arn:aws:ec2:us-east-1:acc-prod-01:instance/i-api01',    'prod-core-api-worker-01',   'acc-prod-01', 2, FALSE, FALSE, TRUE),
('node-settle-01', 'COMPUTE_ASSET',  'arn:aws:ec2:us-east-1:acc-prod-01:instance/i-settle01', 'prod-settlement-engine-01', 'acc-prod-01', 1, FALSE, FALSE, TRUE),
('node-db-01',     'COMPUTE_ASSET',  'arn:aws:ec2:us-east-1:acc-prod-01:instance/i-db01',     'prod-primary-db-master',    'acc-prod-01', 1, FALSE, FALSE, TRUE),
('node-bkt-pii',   'STORAGE_BUCKET', 'arn:aws:s3:::bastion-prod-restricted-pii-vault',        's3-restricted-pii-vault',   'acc-prod-01', 1, FALSE, FALSE, TRUE)
ON CONFLICT (node_id) DO NOTHING;

INSERT INTO graph_edges (edge_id, source_node_id, target_node_id, edge_type, edge_weight, protocol, port_range, action_granted, is_active) VALUES
('ge-01', 'node-edge-01', 'node-web-01',    'NETWORK_INGRESS',   1.0, 'TCP', '8080', 'HTTP_FORWARD', TRUE),
('ge-02', 'node-web-01',  'node-api-01',    'NETWORK_INGRESS',   1.0, 'TCP', '8080', 'RPC_CALL',     TRUE),
('ge-03', 'node-api-01',  'node-settle-01', 'NETWORK_INGRESS',   1.0, 'TCP', '9000', 'SETTLE_TX',    TRUE),
('ge-04', 'node-settle-01','node-db-01',     'NETWORK_INGRESS',   1.0, 'TCP', '5432', 'SQL_QUERY',    TRUE),
('ge-05', 'node-api-01',  'node-bkt-pii',   'HAS_PERMISSION_ON', 1.0, 'ANY', 'ALL',  's3:GetObject', TRUE)
ON CONFLICT (edge_id) DO NOTHING;
