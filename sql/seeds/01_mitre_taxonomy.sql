-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/seeds/01_mitre_taxonomy.sql
-- Description: Comprehensive reference taxonomy for MITRE ATT&CK Enterprise
--              Matrix: Tactics, Techniques, Sub-Techniques, and Detection Guidance.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. MITRE ATT&CK Enterprise Tactics
-- ----------------------------------------------------------------------------

INSERT INTO intel_mitre_tactics (tactic_id, tactic_code, name, description, display_order) VALUES
('tac-01', 'TA0043', 'Reconnaissance',         'Adversary gathers information to plan future adversary operations', 1),
('tac-02', 'TA0042', 'Resource Development',   'Adversary establishes resources supporting future campaign operations', 2),
('tac-03', 'TA0001', 'Initial Access',         'Adversary is attempting to gain initial unauthorized ingress into network', 3),
('tac-04', 'TA0002', 'Execution',              'Adversary executes unauthorized adversary-controlled malicious code', 4),
('tac-05', 'TA0003', 'Persistence',            'Adversary attempts to maintain ongoing persistent access across reboots', 5),
('tac-06', 'TA0004', 'Privilege Escalation',   'Adversary seeks to obtain higher-level permissions on systems or cloud', 6),
('tac-07', 'TA0005', 'Defense Evasion',        'Adversary actively seeks to avoid detection and evade security controls', 7),
('tac-08', 'TA0006', 'Credential Access',      'Adversary attempts to steal credentials such as passwords and keys', 8),
('tac-09', 'TA0007', 'Discovery',              'Adversary attempts to observe and gain knowledge of the environment', 9),
('tac-10', 'TA0008', 'Lateral Movement',       'Adversary pivots through the environment to reach crown jewel targets', 10),
('tac-11', 'TA0009', 'Collection',             'Adversary gathers sensitive business data of target interest', 11),
('tac-12', 'TA0011', 'Command and Control',    'Adversary communicates with compromised systems to control implants', 12),
('tac-13', 'TA0010', 'Exfiltration',           'Adversary attempts to steal and extract data to an external location', 13),
('tac-14', 'TA0040', 'Impact',                 'Adversary attempts to disrupt availability or destroy data assets', 14)
ON CONFLICT (tactic_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. MITRE ATT&CK Primary Techniques (Parent Nodes)
-- ----------------------------------------------------------------------------

INSERT INTO intel_mitre_techniques (technique_id, tactic_id, technique_code, name, is_subtechnique, parent_technique_id, description, detection_guidance) VALUES
('tech-1078',     'tac-03', 'T1078',     'Valid Accounts', FALSE, NULL, 'Adversaries may obtain and abuse credentials of existing accounts to gain initial access.', 'Monitor authentications for unusual geolocations, off-hours access, or absence of MFA.'),
('tech-1190',     'tac-03', 'T1190',     'Exploit Public-Facing Application', FALSE, NULL, 'Adversaries exploit software vulnerabilities in internet-facing web apps.', 'Inspect ingress HTTP access logs for SQL injection, path traversal, or remote code execution.'),
('tech-1133',     'tac-03', 'T1133',     'External Remote Services', FALSE, NULL, 'Adversaries leverage VPN, Citrix, or SSH gateways to gain ingress.', 'Correlate authentication source IPs with known Tor exit nodes and anonymizers.'),

('tech-1059',     'tac-04', 'T1059',     'Command and Scripting Interpreter', FALSE, NULL, 'Adversaries abuse script interpreters to execute commands.', 'Monitor command line arguments for obfuscated or base64 encoded parameters.'),
('tech-1053-005', 'tac-04', 'T1053.005', 'Scheduled Task/Job: Scheduled Task', TRUE, NULL, 'Adversaries abuse task scheduling utilities to execute code.', 'Inspect schtasks and crontab modifications with elevated user context.'),

('tech-1098',     'tac-05', 'T1098',     'Account Manipulation', FALSE, NULL, 'Adversaries manipulate account credentials to maintain persistence.', 'Track generation of secondary access keys and modification of SSH authorized_keys.'),
('tech-1136-003', 'tac-05', 'T1136.003', 'Create Account: Cloud Account', TRUE, NULL, 'Adversaries create rogue IAM accounts for persistent access.', 'Audit CreateUser calls originating from outside CI/CD pipelines.'),

('tech-1548-003', 'tac-06', 'T1548.003', 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching', TRUE, NULL, 'Adversaries abuse sudo permissions to elevate to root.', 'Flag sudo execution by non-standard operational accounts.'),
('tech-1068',     'tac-06', 'T1068',     'Exploitation for Privilege Escalation', FALSE, NULL, 'Adversaries exploit software bugs to elevate privileges.', 'Track unexpected token impersonation and system-level process parentage.'),

('tech-1562-001', 'tac-07', 'T1562.001', 'Impair Defenses: Disable Cloud Logs', TRUE, NULL, 'Adversaries disable logging to hide activity.', 'Alert immediately on StopLogging or DeleteTrail CloudTrail events.'),
('tech-1070-001', 'tac-07', 'T1070.001', 'Indicator Removal: Clear Windows Event Logs', TRUE, NULL, 'Adversaries clear audit logs to remove forensic evidence.', 'Detect execution of wevtutil cl or deletion of /var/log directories.'),
('tech-1036-005', 'tac-07', 'T1036.005', 'Masquerading: Match Legitimate Name or Location', TRUE, NULL, 'Adversaries mimic benign system processes.', 'Flag processes named svchost.exe or systemd running from non-standard directories.'),

('tech-1003-001', 'tac-08', 'T1003.001', 'OS Credential Dumping: LSASS Memory', TRUE, NULL, 'Adversaries dump LSASS process memory to extract plaintext credentials.', 'Identify memory dumping commands targeting lsass.exe via procdump, mimikatz, or comsvcs.'),
('tech-1552-001', 'tac-08', 'T1552.001', 'Unsecured Credentials: Credentials in Files', TRUE, NULL, 'Adversaries search local files for passwords and tokens.', 'Alert on reads of ~/.aws/credentials, ~/.ssh/id_rsa, and credential vaults.'),
('tech-1110-001', 'tac-08', 'T1110.001', 'Brute Force: Password Guessing', TRUE, NULL, 'Adversaries guess passwords through systematic attempts.', 'Detect repeated authentication failures followed by lockout.'),

('tech-1046',     'tac-09', 'T1046',     'Network Service Discovery', FALSE, NULL, 'Adversaries scan remote hosts to enumerate running services.', 'Identify horizontal port sweeps across internal subnets.'),
('tech-1087-004', 'tac-09', 'T1087.004', 'Account Discovery: Cloud Account', TRUE, NULL, 'Adversaries list cloud roles and users.', 'Flag bursts of read-only IAM API queries like GetAccountAuthorizationDetails.'),

('tech-1021-004', 'tac-10', 'T1021.004', 'Remote Services: SSH', TRUE, NULL, 'Adversaries log into remote servers over SSH to move laterally.', 'Detect unexpected SSH ingress from DMZ systems into internal Tier-1 subnets.'),
('tech-1550-002', 'tac-10', 'T1550.002', 'Use Alternate Authentication Material: Pass the Hash', TRUE, NULL, 'Adversaries reuse NTLM hashes or Kerberos tickets.', 'Identify single credential authentications across multiple internal servers in short intervals.'),

('tech-1530',     'tac-11', 'T1530',     'Data from Cloud Storage Object', FALSE, NULL, 'Adversaries access data stored in cloud storage buckets.', 'Monitor bulk GetObject queries on sensitive buckets.'),
('tech-1005',     'tac-11', 'T1005',     'Data from Local System', FALSE, NULL, 'Adversaries stage files locally prior to exfiltration.', 'Alert on automated zip, tar, or 7z archive creation on servers.'),

('tech-1071-001', 'tac-12', 'T1071.001', 'Application Layer Protocol: Web Protocols', TRUE, NULL, 'Adversaries communicate with C2 servers using HTTP/HTTPS.', 'Cross-reference flow logs with threat intelligence C2 IP indicators.'),
('tech-1568-002', 'tac-12', 'T1568.002', 'Dynamic Resolution: Domain Generation Algorithms', TRUE, NULL, 'Adversaries use DGA domains to evade static blacklists.', 'Calculate Shannon entropy and consonant ratios on DNS queries.'),

('tech-1048-003', 'tac-13', 'T1048.003', 'Exfiltration Over Alternative Protocol: DNS Tunneling', TRUE, NULL, 'Adversaries tunnel data out over DNS queries.', 'Identify large volumes of high-length DNS queries with elevated entropy.'),
('tech-1567-002', 'tac-13', 'T1567.002', 'Exfiltration to Cloud Storage', FALSE, NULL, 'Adversaries sync data to external unauthorized cloud storage.', 'Detect rclone, aws s3 sync, or mega-cmd execution.'),

('tech-1485',     'tac-14', 'T1485',     'Data Destruction', FALSE, NULL, 'Adversaries destroy data to disrupt organizational operations.', 'Alert on bulk DeleteBucket or DeleteDBInstance calls.'),
('tech-1486',     'tac-14', 'T1486',     'Data Encrypted for Impact', FALSE, NULL, 'Adversaries encrypt files on target systems to stop operations.', 'Detect rapid file modifications with .enc, .locked, or .crypto extensions.')
ON CONFLICT (technique_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. MITRE ATT&CK Sub-Techniques (Children referencing Parent Techniques)
-- ----------------------------------------------------------------------------

INSERT INTO intel_mitre_techniques (technique_id, tactic_id, technique_code, name, is_subtechnique, parent_technique_id, description, detection_guidance) VALUES
('tech-1078-004', 'tac-03', 'T1078.004', 'Valid Accounts: Cloud Accounts', TRUE, 'tech-1078', 'Adversaries abuse legitimate cloud identity accounts to access cloud environments.', 'Track CloudTrail and IAM ConsoleLogin events where MFA is omitted.'),
('tech-1078-003', 'tac-03', 'T1078.003', 'Valid Accounts: Local Accounts', TRUE, 'tech-1078', 'Adversaries abuse dormant or default local system accounts.', 'Flag logins from accounts dormant for greater than 90 days.'),
('tech-1059-001', 'tac-04', 'T1059.001', 'Command and Scripting Interpreter: PowerShell', TRUE, 'tech-1059', 'Adversaries execute malicious PowerShell scripts.', 'Detect -enc, -encodedcommand, and execution policy bypass flags.'),
('tech-1059-004', 'tac-04', 'T1059.004', 'Command and Scripting Interpreter: Unix Shell', TRUE, 'tech-1059', 'Adversaries execute interactive Unix shell commands.', 'Identify interactive pipelines bound to network sockets such as /dev/tcp or netcat.'),
('tech-1098-001', 'tac-05', 'T1098.001', 'Account Manipulation: Additional Cloud Credentials', TRUE, 'tech-1098', 'Adversaries create extra access keys for target identities.', 'Alert on CreateAccessKey API calls.'),
('tech-1098-004', 'tac-05', 'T1098.004', 'Account Manipulation: SSH Authorized Keys', TRUE, 'tech-1098', 'Adversaries append public keys into ~/.ssh/authorized_keys.', 'Use file integrity monitoring to detect modifications to SSH key stores.')
ON CONFLICT (technique_id) DO NOTHING;
