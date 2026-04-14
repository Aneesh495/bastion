-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/01_core.sql
-- Description: Core infrastructure entities, cloud hierarchy, identity domains,
--              compute assets, network definitions, and credential schemas.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Organizational Hierarchy and Tenant Isolation
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS core_organizations (
    org_id              VARCHAR(64) PRIMARY KEY,
    org_name            VARCHAR(255) NOT NULL,
    root_domain         VARCHAR(255) NOT NULL,
    compliance_framework VARCHAR(64) DEFAULT 'SOC2_TYPE_II',
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS core_cloud_accounts (
    account_id          VARCHAR(64) PRIMARY KEY,
    org_id              VARCHAR(64) NOT NULL REFERENCES core_organizations(org_id),
    provider            VARCHAR(32) NOT NULL CHECK (provider IN ('AWS', 'GCP', 'AZURE', 'ON_PREM')),
    account_name        VARCHAR(255) NOT NULL,
    environment         VARCHAR(32) NOT NULL CHECK (environment IN ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'SANDBOX')),
    region_default      VARCHAR(64) NOT NULL,
    is_isolated         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_organizational_units (
    ou_id               VARCHAR(64) PRIMARY KEY,
    org_id              VARCHAR(64) NOT NULL REFERENCES core_organizations(org_id),
    parent_ou_id        VARCHAR(64) REFERENCES core_organizational_units(ou_id),
    ou_name             VARCHAR(255) NOT NULL,
    tier_level          INTEGER NOT NULL DEFAULT 1,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. Identity and Access Management (IAM) Primitives
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS core_identity_principals (
    principal_id        VARCHAR(64) PRIMARY KEY,
    org_id              VARCHAR(64) NOT NULL REFERENCES core_organizations(org_id),
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    principal_type      VARCHAR(32) NOT NULL CHECK (principal_type IN ('HUMAN_USER', 'SERVICE_ACCOUNT', 'FEDERATED_ROLE', 'SYSTEM_AGENT')),
    username            VARCHAR(128) NOT NULL,
    email               VARCHAR(255),
    arn                 VARCHAR(512) NOT NULL UNIQUE,
    department          VARCHAR(128),
    clearance_level     VARCHAR(32) NOT NULL DEFAULT 'STANDARD' CHECK (clearance_level IN ('PUBLIC', 'STANDARD', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET')),
    is_service_account  BOOLEAN NOT NULL DEFAULT FALSE,
    is_privileged       BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enforced        BOOLEAN NOT NULL DEFAULT TRUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at       TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_iam_groups (
    group_id            VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    group_name          VARCHAR(128) NOT NULL,
    arn                 VARCHAR(512) NOT NULL UNIQUE,
    description         TEXT,
    is_admin_tier       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_iam_group_memberships (
    membership_id       VARCHAR(64) PRIMARY KEY,
    group_id            VARCHAR(64) NOT NULL REFERENCES core_iam_groups(group_id),
    principal_id        VARCHAR(64) NOT NULL REFERENCES core_identity_principals(principal_id),
    assigned_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by         VARCHAR(64) NOT NULL,
    CONSTRAINT uq_group_principal UNIQUE (group_id, principal_id)
);

CREATE TABLE IF NOT EXISTS core_iam_roles (
    role_id             VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    role_name           VARCHAR(128) NOT NULL,
    arn                 VARCHAR(512) NOT NULL UNIQUE,
    trust_policy_json   TEXT NOT NULL,
    max_session_seconds INTEGER NOT NULL DEFAULT 3600,
    is_cross_account    BOOLEAN NOT NULL DEFAULT FALSE,
    is_instance_profile BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_iam_policies (
    policy_id           VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    policy_name         VARCHAR(128) NOT NULL,
    arn                 VARCHAR(512) NOT NULL UNIQUE,
    policy_type         VARCHAR(32) NOT NULL CHECK (policy_type IN ('MANAGED', 'INLINE', 'BOUNDARY', 'SERVICE_CONTROL')),
    document_json       TEXT NOT NULL,
    is_overprivileged   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_iam_policy_statements (
    statement_id        VARCHAR(64) PRIMARY KEY,
    policy_id           VARCHAR(64) NOT NULL REFERENCES core_iam_policies(policy_id),
    effect              VARCHAR(8) NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    action_pattern      VARCHAR(255) NOT NULL,
    resource_pattern    VARCHAR(512) NOT NULL,
    condition_operator  VARCHAR(64),
    condition_key       VARCHAR(128),
    condition_value     VARCHAR(512)
);

CREATE TABLE IF NOT EXISTS core_iam_policy_attachments (
    attachment_id       VARCHAR(64) PRIMARY KEY,
    policy_id           VARCHAR(64) NOT NULL REFERENCES core_iam_policies(policy_id),
    principal_id        VARCHAR(64) REFERENCES core_identity_principals(principal_id),
    group_id            VARCHAR(64) REFERENCES core_iam_groups(group_id),
    role_id             VARCHAR(64) REFERENCES core_iam_roles(role_id),
    attached_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_credentials (
    credential_id       VARCHAR(64) PRIMARY KEY,
    principal_id        VARCHAR(64) NOT NULL REFERENCES core_identity_principals(principal_id),
    credential_type     VARCHAR(32) NOT NULL CHECK (credential_type IN ('PASSWORD_HASH', 'API_ACCESS_KEY', 'SSH_PUBLIC_KEY', 'X509_CERTIFICATE', 'OAUTH_TOKEN')),
    key_fingerprint     VARCHAR(128) NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP,
    is_compromised      BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

-- ----------------------------------------------------------------------------
-- 3. Network Architecture and Boundary Topologies
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS core_virtual_networks (
    vnet_id             VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    vnet_name           VARCHAR(128) NOT NULL,
    cidr_block          VARCHAR(64) NOT NULL,
    is_peered           BOOLEAN NOT NULL DEFAULT FALSE,
    has_internet_gateway BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_subnets (
    subnet_id           VARCHAR(64) PRIMARY KEY,
    vnet_id             VARCHAR(64) NOT NULL REFERENCES core_virtual_networks(vnet_id),
    subnet_name         VARCHAR(128) NOT NULL,
    cidr_block          VARCHAR(64) NOT NULL,
    zone                VARCHAR(64) NOT NULL,
    zone_type           VARCHAR(32) NOT NULL CHECK (zone_type IN ('DMZ', 'APPLICATION', 'DATA', 'SECURITY_ISOLATED')),
    is_public           BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_security_groups (
    sg_id               VARCHAR(64) PRIMARY KEY,
    vnet_id             VARCHAR(64) NOT NULL REFERENCES core_virtual_networks(vnet_id),
    sg_name             VARCHAR(128) NOT NULL,
    description         TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_security_group_rules (
    rule_id             VARCHAR(64) PRIMARY KEY,
    sg_id               VARCHAR(64) NOT NULL REFERENCES core_security_groups(sg_id),
    direction           VARCHAR(8) NOT NULL CHECK (direction IN ('INBOUND', 'OUTBOUND')),
    protocol            VARCHAR(16) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'ALL')),
    from_port           INTEGER NOT NULL,
    to_port             INTEGER NOT NULL,
    remote_cidr         VARCHAR(64),
    remote_sg_id        VARCHAR(64) REFERENCES core_security_groups(sg_id),
    rule_action         VARCHAR(8) NOT NULL DEFAULT 'ALLOW' CHECK (rule_action IN ('ALLOW', 'DENY')),
    description         TEXT
);

-- ----------------------------------------------------------------------------
-- 4. Infrastructure Assets and Workloads
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS core_compute_assets (
    asset_id            VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    subnet_id           VARCHAR(64) NOT NULL REFERENCES core_subnets(subnet_id),
    asset_type          VARCHAR(32) NOT NULL CHECK (asset_type IN ('VM_INSTANCE', 'BARE_METAL', 'CONTAINER_POD', 'SERVERLESS_FUNCTION')),
    hostname            VARCHAR(255) NOT NULL,
    primary_ip          VARCHAR(64) NOT NULL,
    public_ip           VARCHAR(64),
    mac_address         VARCHAR(32) NOT NULL,
    os_distribution     VARCHAR(64) NOT NULL,
    os_version          VARCHAR(64) NOT NULL,
    assigned_role_id    VARCHAR(64) REFERENCES core_iam_roles(role_id),
    is_crown_jewel      BOOLEAN NOT NULL DEFAULT FALSE,
    criticality_score   NUMERIC(5,2) NOT NULL DEFAULT 50.00 CHECK (criticality_score BETWEEN 0.0 AND 100.0),
    is_compromised      BOOLEAN NOT NULL DEFAULT FALSE,
    is_quarantined      BOOLEAN NOT NULL DEFAULT FALSE,
    state               VARCHAR(32) NOT NULL DEFAULT 'RUNNING' CHECK (state IN ('RUNNING', 'STOPPED', 'TERMINATED', 'ISOLATED')),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_storage_buckets (
    bucket_id           VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    bucket_name         VARCHAR(255) NOT NULL UNIQUE,
    data_classification VARCHAR(32) NOT NULL CHECK (data_classification IN ('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED_PII')),
    encryption_algorithm VARCHAR(64) NOT NULL DEFAULT 'AES256',
    is_publicly_readable BOOLEAN NOT NULL DEFAULT FALSE,
    versioning_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    logging_enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core_database_clusters (
    cluster_id          VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    subnet_id           VARCHAR(64) NOT NULL REFERENCES core_subnets(subnet_id),
    engine_name         VARCHAR(64) NOT NULL,
    engine_version      VARCHAR(32) NOT NULL,
    is_public           BOOLEAN NOT NULL DEFAULT FALSE,
    is_multi_az         BOOLEAN NOT NULL DEFAULT TRUE,
    is_encrypted_at_rest BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indices for rapid relational joins
CREATE INDEX IF NOT EXISTS idx_principals_account ON core_identity_principals(account_id);
CREATE INDEX IF NOT EXISTS idx_principals_arn ON core_identity_principals(arn);
CREATE INDEX IF NOT EXISTS idx_assets_subnet ON core_compute_assets(subnet_id);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON core_compute_assets(primary_ip);
CREATE INDEX IF NOT EXISTS idx_subnets_vnet ON core_subnets(vnet_id);
CREATE INDEX IF NOT EXISTS idx_sg_rules_sg ON core_security_group_rules(sg_id);
