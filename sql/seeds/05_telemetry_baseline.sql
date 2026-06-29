-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/seeds/05_telemetry_baseline.sql
-- Description: Multi-tenant enterprise benign baseline telemetry: normal VPC flows,
--              routine IAM authentications with MFA, standard DNS lookups, and processes.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Ephemeral IP Lease Allocations
-- ----------------------------------------------------------------------------

INSERT INTO entity_asset_ip_leases (lease_id, asset_id, ip_address, mac_address, lease_start, lease_end, interface_id, is_primary) VALUES
('lease-01', 'ast-edge-01',   '10.0.1.10', '02:42:0a:00:01:0a', '2026-10-01 00:00:00', NULL, 'eni-edge-01',   TRUE),
('lease-02', 'ast-web-01',    '10.0.1.55', '02:42:0a:00:01:37', '2026-10-01 00:00:00', NULL, 'eni-web-01',    TRUE),
('lease-03', 'ast-api-01',    '10.0.2.20', '02:42:0a:00:02:14', '2026-10-01 00:00:00', NULL, 'eni-api-01',    TRUE),
('lease-04', 'ast-settle-01', '10.0.3.15', '02:42:0a:00:03:0f', '2026-10-01 00:00:00', NULL, 'eni-settle-01', TRUE),
('lease-05', 'ast-db-01',     '10.0.3.50', '02:42:0a:00:03:32', '2026-10-01 00:00:00', NULL, 'eni-db-01',     TRUE)
ON CONFLICT (lease_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. Benign Authentication Telemetry
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_authentication_events (
    auth_event_id, account_id, event_time, principal_id, username_asserted,
    auth_protocol, auth_status, source_ip, source_country, source_city,
    source_latitude, source_longitude, user_agent, mfa_authenticated, mfa_method
) VALUES
('auth-b-01', 'acc-prod-01', '2026-10-15 08:30:00', 'usr-admin-01',   'alice.admin',     'SAML_2_0', 'SUCCESS', '198.51.100.12', 'US', 'New York', 40.7128, -74.0060, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', TRUE, 'FIDO2_WEBAUTHN'),
('auth-b-02', 'acc-prod-01', '2026-10-15 09:00:00', 'usr-devops-01',  'bob.devops',      'OIDC',     'SUCCESS', '198.51.100.15', 'US', 'Boston',   42.3601, -71.0589, 'Mozilla/5.0 (X11; Linux x86_64)',            TRUE, 'TOTP'),
('auth-b-03', 'acc-prod-01', '2026-10-15 09:15:00', 'usr-analyst-01', 'charlie.analyst', 'OIDC',     'SUCCESS', '198.51.100.22', 'US', 'New York', 40.7128, -74.0060, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',    TRUE, 'TOTP'),
('auth-b-04', 'acc-dev-01',  '2026-10-15 10:00:00', 'usr-intern-01',  'dave.intern',     'PASSWORD', 'SUCCESS', '198.51.100.30', 'US', 'Austin',   30.2672, -97.7431, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', TRUE, 'TOTP'),
('auth-b-05', 'acc-prod-01', '2026-10-15 10:30:00', 'usr-admin-01',   'alice.admin',     'SAML_2_0', 'SUCCESS', '198.51.100.12', 'US', 'New York', 40.7128, -74.0060, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', TRUE, 'FIDO2_WEBAUTHN')
ON CONFLICT (auth_event_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. Benign DNS Telemetry
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_dns_queries (query_id, asset_id, query_time, client_ip, query_name, query_type, response_code, resolved_ip, ttl_seconds, entropy_score) VALUES
('dns-b-01', 'ast-edge-01', '2026-10-15 08:00:01', '10.0.1.10', 'bastion-sec.internal', 'A', 'NOERROR', '10.0.1.10', 300, 2.45),
('dns-b-02', 'ast-web-01',  '2026-10-15 08:00:05', '10.0.1.55', 'api.github.com',        'A', 'NOERROR', '140.82.112.5', 300, 2.70),
('dns-b-03', 'ast-api-01',  '2026-10-15 08:01:00', '10.0.2.20', 'rds.amazonaws.com',     'A', 'NOERROR', '10.0.3.50', 300, 2.65),
('dns-b-04', 'ast-edge-01', '2026-10-15 08:02:10', '10.0.1.10', 'google.com',           'A', 'NOERROR', '142.250.190.46', 300, 2.15),
('dns-b-05', 'ast-api-01',  '2026-10-15 08:03:00', '10.0.2.20', 'pypi.org',             'A', 'NOERROR', '151.101.0.223', 300, 2.20)
ON CONFLICT (query_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. Benign HTTP Ingress Traffic
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_http_access_logs (
    request_id, asset_id, request_time, client_ip, http_method, uri_path,
    query_string, status_code, bytes_sent, duration_ms, user_agent
) VALUES
('http-b-01', 'ast-edge-01', '2026-10-15 08:05:00', '198.51.100.12', 'GET',  '/index.html',         NULL,              200, 4520,  12, 'Mozilla/5.0'),
('http-b-02', 'ast-edge-01', '2026-10-15 08:05:02', '198.51.100.12', 'GET',  '/static/css/main.css',NULL,              200, 12800,  8, 'Mozilla/5.0'),
('http-b-03', 'ast-edge-01', '2026-10-15 08:05:05', '198.51.100.12', 'GET',  '/api/v1/health',      NULL,              200, 240,    4, 'Mozilla/5.0'),
('http-b-04', 'ast-web-01',  '2026-10-15 08:10:00', '10.0.1.10',    'POST', '/api/v1/login',       NULL,              200, 650,   35, 'BastionClient/1.0'),
('http-b-05', 'ast-web-01',  '2026-10-15 08:15:00', '10.0.1.10',    'GET',  '/api/v1/dashboard',   'view=summary',    200, 8900,  22, 'Mozilla/5.0')
ON CONFLICT (request_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 5. Benign Process Execution Trees
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_process_events (
    process_guid, asset_id, parent_process_guid, pid, ppid, event_time,
    process_name, process_path, command_line, executing_user, hash_sha256, is_elevated, integrity_level
) VALUES
('proc-b-01', 'ast-edge-01', NULL,        1,    0, '2026-10-15 00:00:01', 'systemd', '/lib/systemd/systemd', '/sbin/init', 'root', 'a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123', TRUE, 'SYSTEM'),
('proc-b-02', 'ast-edge-01', 'proc-b-01', 512,  1, '2026-10-15 00:00:10', 'nginx',   '/usr/sbin/nginx',       'nginx -g daemon off;', 'www-data', 'b2c3d4e5f6a10123456789abcdef0123456789abcdef0123456789abcdef0123', FALSE, 'MEDIUM'),
('proc-b-03', 'ast-api-01',  NULL,        1024, 1, '2026-10-15 00:00:15', 'python3', '/usr/bin/python3',     'python3 app.py --port 8080', 'appuser', 'c3d4e5f6a1b20123456789abcdef0123456789abcdef0123456789abcdef0123', FALSE, 'MEDIUM'),
('proc-b-04', 'ast-settle-01',NULL,       2048, 1, '2026-10-15 00:00:20', 'settle',  '/opt/bin/settle',       '/opt/bin/settle --worker', 'settleuser', 'd4e5f6a1b2c30123456789abcdef0123456789abcdef0123456789abcdef0123', FALSE, 'HIGH')
ON CONFLICT (process_guid) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 6. Benign Routine VPC Flow Traffic
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_vpc_flow_logs (
    flow_id, account_id, interface_id, src_addr, dst_addr, src_port, dst_port,
    protocol, packets, bytes_transferred, start_time, end_time, action
) VALUES
('fl-b-01', 'acc-prod-01', 'eni-edge-01', '203.0.113.15', '10.0.1.10', 44320, 443,  6, 32, 14500, '2026-10-15 08:00:00', '2026-10-15 08:00:30', 'ACCEPT'),
('fl-b-02', 'acc-prod-01', 'eni-edge-01', '10.0.1.10',    '10.0.2.20', 51200, 8080, 6, 25, 8900,  '2026-10-15 08:00:32', '2026-10-15 08:00:45', 'ACCEPT'),
('fl-b-03', 'acc-prod-01', 'eni-api-01',  '10.0.2.20',    '10.0.3.50', 48900, 5432, 6, 18, 4200,  '2026-10-15 08:00:46', '2026-10-15 08:00:50', 'ACCEPT'),
('fl-b-04', 'acc-prod-01', 'eni-api-01',  '10.0.2.20',    '10.0.3.15', 52100, 9000, 6, 12, 2800,  '2026-10-15 08:01:00', '2026-10-15 08:01:10', 'ACCEPT'),
('fl-b-05', 'acc-prod-01', 'eni-edge-01', '192.0.2.99',   '10.0.1.10', 38200, 22,   6, 2,  120,   '2026-10-15 08:02:00', '2026-10-15 08:02:01', 'REJECT')
ON CONFLICT (flow_id) DO NOTHING;
