-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/seeds/03_iam_hierarchy.sql
-- Description: Multi-tier IAM hierarchy: Principals, Groups, Roles, Policies,
--              Permission Statements, Role Attachments, and Cryptographic Credentials.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Identity Principals (Human Users and Service Accounts)
-- ----------------------------------------------------------------------------

INSERT INTO core_identity_principals (
    principal_id, org_id, account_id, principal_type, username, email, arn,
    department, clearance_level, is_service_account, is_privileged, mfa_enforced, is_active, last_login_at
) VALUES
('usr-admin-01',   'org-01', 'acc-prod-01', 'HUMAN_USER',      'alice.admin',     'alice.admin@bastion-sec.internal',     'arn:aws:iam::acc-prod-01:user/alice.admin',     'Cloud Engineering', 'TOP_SECRET',   FALSE, TRUE,  TRUE,  TRUE, '2026-10-15 08:30:00'),
('usr-devops-01',  'org-01', 'acc-prod-01', 'HUMAN_USER',      'bob.devops',      'bob.devops@bastion-sec.internal',      'arn:aws:iam::acc-prod-01:user/bob.devops',      'Platform SRE',      'SECRET',       FALSE, TRUE,  TRUE,  TRUE, '2026-10-15 09:15:00'),
('usr-analyst-01', 'org-01', 'acc-prod-01', 'HUMAN_USER',      'charlie.analyst', 'charlie.analyst@bastion-sec.internal', 'arn:aws:iam::acc-prod-01:user/charlie.analyst', 'Data Science',      'CONFIDENTIAL', FALSE, FALSE, TRUE,  TRUE, '2026-10-14 17:00:00'),
('usr-intern-01',  'org-01', 'acc-dev-01',  'HUMAN_USER',      'dave.intern',     'dave.intern@bastion-sec.internal',     'arn:aws:iam::acc-dev-01:user/dave.intern',      'Engineering',       'STANDARD',     FALSE, FALSE, FALSE, TRUE, '2026-10-12 11:20:00'),
('usr-dormant-01', 'org-01', 'acc-prod-01', 'HUMAN_USER',      'eve.contractor',  'eve.contractor@bastion-sec.internal',  'arn:aws:iam::acc-prod-01:user/eve.contractor',  'External Audit',    'STANDARD',     FALSE, FALSE, FALSE, TRUE, '2026-05-01 10:00:00'),
('svc-billing-01', 'org-01', 'acc-prod-01', 'SERVICE_ACCOUNT', 'svc-billing-etl', 'svc-billing@bastion-sec.internal',     'arn:aws:iam::acc-prod-01:user/svc-billing-etl', 'FinOps',           'SECRET',       TRUE,  FALSE, FALSE, TRUE, '2026-10-15 00:00:00'),
('svc-backup-01',  'org-01', 'acc-prod-01', 'SERVICE_ACCOUNT', 'svc-backup-agent','svc-backup@bastion-sec.internal',      'arn:aws:iam::acc-prod-01:user/svc-backup-agent','Infrastructure',   'TOP_SECRET',   TRUE,  TRUE,  FALSE, TRUE, '2026-10-15 03:00:00')
ON CONFLICT (principal_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. IAM Groups and Memberships
-- ----------------------------------------------------------------------------

INSERT INTO core_iam_groups (group_id, account_id, group_name, arn, description, is_admin_tier) VALUES
('grp-admins',   'acc-prod-01', 'CloudAdministrators', 'arn:aws:iam::acc-prod-01:group/CloudAdministrators', 'Tier-1 Root Cloud Administrators', TRUE),
('grp-devops',   'acc-prod-01', 'DevOpsEngineers',     'arn:aws:iam::acc-prod-01:group/DevOpsEngineers',     'Infrastructure and CI/CD operations', FALSE),
('grp-analysts', 'acc-prod-01', 'DataAnalysts',        'arn:aws:iam::acc-prod-01:group/DataAnalysts',        'Read-only analytical querying tier', FALSE)
ON CONFLICT (group_id) DO NOTHING;

INSERT INTO core_iam_group_memberships (membership_id, group_id, principal_id, assigned_by) VALUES
('mem-01', 'grp-admins',   'usr-admin-01',   'SYSTEM_INIT'),
('mem-02', 'grp-devops',   'usr-devops-01',  'usr-admin-01'),
('mem-03', 'grp-analysts', 'usr-analyst-01', 'usr-admin-01'),
('mem-04', 'grp-analysts', 'usr-intern-01',  'usr-devops-01')
ON CONFLICT (membership_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. IAM Roles and Trust Policies
-- ----------------------------------------------------------------------------

INSERT INTO core_iam_roles (role_id, account_id, role_name, arn, trust_policy_json, max_session_seconds, is_cross_account, is_instance_profile) VALUES
('role-admin-breakglass', 'acc-prod-01', 'AdminBreakGlassRole', 'arn:aws:iam::acc-prod-01:role/AdminBreakGlassRole', '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::acc-prod-01:user/alice.admin"},"Action":"sts:AssumeRole"}]}', 3600, FALSE, FALSE),
('role-ec2-worker',       'acc-prod-01', 'EC2WorkerProfileRole', 'arn:aws:iam::acc-prod-01:role/EC2WorkerProfileRole', '{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}', 7200, FALSE, TRUE),
('role-lambda-processor', 'acc-prod-01', 'LambdaProcessorRole', 'arn:aws:iam::acc-prod-01:role/LambdaProcessorRole', '{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}', 900, FALSE, FALSE)
ON CONFLICT (role_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. IAM Policies and Declarative Permission Statements
-- ----------------------------------------------------------------------------

INSERT INTO core_iam_policies (policy_id, account_id, policy_name, arn, policy_type, document_json, is_overprivileged) VALUES
('pol-admin',   'acc-prod-01', 'AdministratorAccess',  'arn:aws:iam::aws:policy/AdministratorAccess',             'MANAGED', '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}', TRUE),
('pol-devops',  'acc-prod-01', 'DevOpsAutomation',     'arn:aws:iam::acc-prod-01:policy/DevOpsAutomation',        'MANAGED', '{"Statement":[{"Effect":"Allow","Action":["ec2:*","s3:*","iam:PassRole"],"Resource":"*"}]}', FALSE),
('pol-pii-read','acc-prod-01', 'PIIVaultReadOnly',     'arn:aws:iam::acc-prod-01:policy/PIIVaultReadOnly',        'MANAGED', '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bastion-prod-restricted-pii-vault/*"}]}', FALSE),
('pol-deny-log','acc-prod-01', 'DenyAuditLogTampering','arn:aws:iam::acc-prod-01:policy/DenyAuditLogTampering',   'MANAGED', '{"Statement":[{"Effect":"Deny","Action":["cloudtrail:StopLogging","cloudtrail:DeleteTrail"],"Resource":"*"}]}', FALSE)
ON CONFLICT (policy_id) DO NOTHING;

INSERT INTO core_iam_policy_statements (statement_id, policy_id, effect, action_pattern, resource_pattern) VALUES
('stmt-01', 'pol-admin',    'ALLOW', '*', '*'),
('stmt-02', 'pol-devops',   'ALLOW', 'ec2:*', '*'),
('stmt-03', 'pol-devops',   'ALLOW', 's3:*', '*'),
('stmt-04', 'pol-devops',   'ALLOW', 'iam:PassRole', '*'),
('stmt-05', 'pol-devops',   'ALLOW', 'lambda:CreateFunction', '*'),
('stmt-06', 'pol-devops',   'ALLOW', 'lambda:InvokeFunction', '*'),
('stmt-07', 'pol-pii-read', 'ALLOW', 's3:GetObject', 'arn:aws:s3:::bastion-prod-restricted-pii-vault/*'),
('stmt-08', 'pol-deny-log', 'DENY',  'cloudtrail:StopLogging', '*'),
('stmt-09', 'pol-deny-log', 'DENY',  'cloudtrail:DeleteTrail', '*')
ON CONFLICT (statement_id) DO NOTHING;

INSERT INTO core_iam_policy_attachments (attachment_id, policy_id, principal_id, group_id, role_id) VALUES
('att-01', 'pol-admin',    NULL,           'grp-admins', NULL),
('att-02', 'pol-devops',   NULL,           'grp-devops', NULL),
('att-03', 'pol-pii-read', NULL,           'grp-analysts', NULL),
('att-04', 'pol-deny-log', NULL,           'grp-admins', NULL),
('att-05', 'pol-admin',    NULL,           NULL,         'role-admin-breakglass')
ON CONFLICT (attachment_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 5. Cryptographic Credentials and API Access Keys
-- ----------------------------------------------------------------------------

INSERT INTO core_credentials (credential_id, principal_id, credential_type, key_fingerprint, is_compromised, is_active) VALUES
('cred-01', 'usr-admin-01',   'API_ACCESS_KEY',  'AKIAIOSFODNN7EXAMPLE', FALSE, TRUE),
('cred-02', 'usr-devops-01',  'API_ACCESS_KEY',  'AKIAI44QH8DHBEXAMPLE', FALSE, TRUE),
('cred-03', 'usr-dormant-01', 'API_ACCESS_KEY',  'AKIAJSIE234JSEXAMPLE', FALSE, TRUE),
('cred-04', 'svc-billing-01', 'API_ACCESS_KEY',  'AKIA998877665EXAMPLE', FALSE, TRUE),
('cred-05', 'usr-admin-01',   'SSH_PUBLIC_KEY',  'SHA256:4x8q1b9c2a8f3e',FALSE, TRUE)
ON CONFLICT (credential_id) DO NOTHING;
