-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/02_telemetry.sql
-- Description: High-throughput security telemetry event schemas, flow logs,
--              authentication events, cloud audit trails, process execution trees,
--              DNS requests, HTTP access, and file integrity modification logs.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Virtual Private Cloud (VPC) Flow Logs
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_vpc_flow_logs (
    flow_id             VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    interface_id        VARCHAR(64) NOT NULL,
    src_addr            VARCHAR(64) NOT NULL,
    dst_addr            VARCHAR(64) NOT NULL,
    src_port            INTEGER NOT NULL,
    dst_port            INTEGER NOT NULL,
    protocol            INTEGER NOT NULL, -- IANA Protocol Number (6=TCP, 17=UDP, 1=ICMP)
    packets             BIGINT NOT NULL CHECK (packets >= 0),
    bytes_transferred   BIGINT NOT NULL CHECK (bytes_transferred >= 0),
    start_time          TIMESTAMP NOT NULL,
    end_time            TIMESTAMP NOT NULL,
    action              VARCHAR(8) NOT NULL CHECK (action IN ('ACCEPT', 'REJECT')),
    tcp_flags           INTEGER DEFAULT 0,
    log_status          VARCHAR(16) NOT NULL DEFAULT 'OK',
    CONSTRAINT chk_flow_duration CHECK (end_time >= start_time)
);

-- ----------------------------------------------------------------------------
-- 2. Identity and Authentication Audit Events
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_authentication_events (
    auth_event_id       VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    event_time          TIMESTAMP NOT NULL,
    principal_id        VARCHAR(64) REFERENCES core_identity_principals(principal_id),
    username_asserted   VARCHAR(128) NOT NULL,
    auth_protocol       VARCHAR(32) NOT NULL CHECK (auth_protocol IN ('SAML_2_0', 'OIDC', 'KERBEROS', 'NTLM', 'SSH', 'PASSWORD', 'MUTUAL_TLS')),
    auth_status         VARCHAR(16) NOT NULL CHECK (auth_status IN ('SUCCESS', 'FAILURE', 'CHALLENGE_REQUIRED')),
    failure_reason      VARCHAR(128),
    source_ip           VARCHAR(64) NOT NULL,
    source_country      VARCHAR(8),
    source_city         VARCHAR(64),
    source_latitude     NUMERIC(8,4),
    source_longitude    NUMERIC(8,4),
    user_agent          VARCHAR(512),
    mfa_authenticated   BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_method          VARCHAR(32) CHECK (mfa_method IN ('TOTP', 'FIDO2_WEBAUTHN', 'SMS', 'PUSH', 'NONE')),
    session_id          VARCHAR(128),
    target_resource     VARCHAR(255)
);

-- ----------------------------------------------------------------------------
-- 3. Cloud Infrastructure Control-Plane Audit Events
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_cloudtrail_events (
    event_id            VARCHAR(64) PRIMARY KEY,
    account_id          VARCHAR(64) NOT NULL REFERENCES core_cloud_accounts(account_id),
    event_time          TIMESTAMP NOT NULL,
    event_source        VARCHAR(128) NOT NULL, -- e.g. iam.amazonaws.com, s3.amazonaws.com
    event_name          VARCHAR(128) NOT NULL, -- e.g. CreateAccessKey, PutBucketPolicy
    principal_id        VARCHAR(64) REFERENCES core_identity_principals(principal_id),
    principal_arn       VARCHAR(512) NOT NULL,
    source_ip_address   VARCHAR(64) NOT NULL,
    user_agent          VARCHAR(512),
    request_parameters  TEXT,                  -- Serialized JSON parameters
    response_elements   TEXT,                  -- Serialized JSON response
    read_only           BOOLEAN NOT NULL DEFAULT FALSE,
    status_code         INTEGER NOT NULL DEFAULT 200,
    error_code          VARCHAR(128),
    error_message       TEXT
);

-- ----------------------------------------------------------------------------
-- 4. Endpoint Process Execution Trees
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_process_events (
    process_guid        VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    parent_process_guid VARCHAR(64),
    pid                 INTEGER NOT NULL,
    ppid                INTEGER NOT NULL,
    event_time          TIMESTAMP NOT NULL,
    process_name        VARCHAR(255) NOT NULL,
    process_path        VARCHAR(512) NOT NULL,
    command_line        TEXT NOT NULL,
    executing_user      VARCHAR(128) NOT NULL,
    hash_sha256         VARCHAR(64) NOT NULL,
    is_elevated         BOOLEAN NOT NULL DEFAULT FALSE,
    integrity_level     VARCHAR(32) DEFAULT 'MEDIUM' CHECK (integrity_level IN ('LOW', 'MEDIUM', 'HIGH', 'SYSTEM')),
    exit_code           INTEGER,
    terminated_at       TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 5. Domain Name Service (DNS) Queries
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_dns_queries (
    query_id            VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    query_time          TIMESTAMP NOT NULL,
    client_ip           VARCHAR(64) NOT NULL,
    query_name          VARCHAR(255) NOT NULL,
    query_type          VARCHAR(16) NOT NULL CHECK (query_type IN ('A', 'AAAA', 'CNAME', 'TXT', 'MX', 'PTR', 'NS', 'SRV')),
    response_code       VARCHAR(16) NOT NULL CHECK (response_code IN ('NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED')),
    resolved_ip         VARCHAR(64),
    ttl_seconds         INTEGER NOT NULL DEFAULT 300,
    entropy_score       NUMERIC(5,2) DEFAULT 0.0 -- Calculated Shannon entropy of domain string
);

-- ----------------------------------------------------------------------------
-- 6. HTTP and Ingress API Access Logs
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_http_access_logs (
    request_id          VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    request_time        TIMESTAMP NOT NULL,
    client_ip           VARCHAR(64) NOT NULL,
    http_method         VARCHAR(16) NOT NULL CHECK (http_method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')),
    uri_path            VARCHAR(512) NOT NULL,
    query_string        TEXT,
    http_version        VARCHAR(16) NOT NULL DEFAULT 'HTTP/1.1',
    status_code         INTEGER NOT NULL,
    bytes_sent          BIGINT NOT NULL DEFAULT 0,
    duration_ms         INTEGER NOT NULL DEFAULT 0,
    user_agent          VARCHAR(512),
    referer             VARCHAR(512)
);

-- ----------------------------------------------------------------------------
-- 7. File Integrity Monitoring (FIM) and System Modifications
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS telemetry_file_modifications (
    modification_id     VARCHAR(64) PRIMARY KEY,
    asset_id            VARCHAR(64) NOT NULL REFERENCES core_compute_assets(asset_id),
    process_guid        VARCHAR(64) REFERENCES telemetry_process_events(process_guid),
    event_time          TIMESTAMP NOT NULL,
    file_path           VARCHAR(512) NOT NULL,
    action              VARCHAR(16) NOT NULL CHECK (action IN ('CREATED', 'MODIFIED', 'DELETED', 'PERMISSIONS_CHANGED')),
    previous_sha256     VARCHAR(64),
    new_sha256          VARCHAR(64),
    file_size_bytes     BIGINT NOT NULL DEFAULT 0,
    is_sensitive_path   BOOLEAN NOT NULL DEFAULT FALSE
);

-- Strategic indices for high-velocity temporal lookups
CREATE INDEX IF NOT EXISTS idx_flow_time_src ON telemetry_vpc_flow_logs(start_time, src_addr);
CREATE INDEX IF NOT EXISTS idx_flow_dst_port ON telemetry_vpc_flow_logs(dst_addr, dst_port);
CREATE INDEX IF NOT EXISTS idx_auth_time_principal ON telemetry_authentication_events(event_time, principal_id);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON telemetry_authentication_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_source_event ON telemetry_cloudtrail_events(event_source, event_name);
CREATE INDEX IF NOT EXISTS idx_cloudtrail_time ON telemetry_cloudtrail_events(event_time);
CREATE INDEX IF NOT EXISTS idx_process_asset_time ON telemetry_process_events(asset_id, event_time);
CREATE INDEX IF NOT EXISTS idx_process_hash ON telemetry_process_events(hash_sha256);
CREATE INDEX IF NOT EXISTS idx_dns_name_time ON telemetry_dns_queries(query_name, query_time);
CREATE INDEX IF NOT EXISTS idx_http_time_ip ON telemetry_http_access_logs(request_time, client_ip);
CREATE INDEX IF NOT EXISTS idx_fim_asset_file ON telemetry_file_modifications(asset_id, file_path);
