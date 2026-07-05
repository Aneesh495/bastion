-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/graph/toxic_combinations.sql
-- Description: Separation of Duties (SoD) conflict detection and toxic permission
--              combination analysis across cloud IAM and infrastructure layers.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Toxic Permission Combinations Catalog and Detection
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_toxic_combinations AS
WITH perms AS (
    SELECT DISTINCT
        principal_id,
        username,
        action_pattern
    FROM v_iam_effective_permissions
    WHERE evaluation_verdict = 'EFFECTIVE_ALLOW'
),
-- Toxic Combo 1: Audit Log Destruction + CloudTrail Disabling
c1_trail_destruction AS (
    SELECT
        p1.principal_id,
        p1.username,
        'TOXIC_COMBO_01_LOG_DESTRUCTION' AS combo_code,
        'CRITICAL' AS severity,
        99.0 AS toxic_score,
        'Possesses both CloudTrail log disabling and S3 bucket deletion privileges' AS hazard_description
    FROM perms p1
    JOIN perms p2 ON p1.principal_id = p2.principal_id
    WHERE (p1.action_pattern IN ('cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'cloudtrail:*', '*'))
      AND (p2.action_pattern IN ('s3:DeleteBucket', 's3:DeleteObject', 's3:*', '*'))
),
-- Toxic Combo 2: Cryptographic Key Destruction + Database Deletion (Ransomware Primitive)
c2_ransomware_primitive AS (
    SELECT
        p1.principal_id,
        p1.username,
        'TOXIC_COMBO_02_RANSOMWARE_PRIMITIVE' AS combo_code,
        'CRITICAL' AS severity,
        100.0 AS toxic_score,
        'Possesses both KMS key destruction and database cluster deletion privileges' AS hazard_description
    FROM perms p1
    JOIN perms p2 ON p1.principal_id = p2.principal_id
    WHERE (p1.action_pattern IN ('kms:ScheduleKeyDeletion', 'kms:DisableKey', 'kms:*', '*'))
      AND (p2.action_pattern IN ('rds:DeleteDBInstance', 'rds:DeleteDBCluster', 'rds:*', '*'))
),
-- Toxic Combo 3: Identity Provider Poisoning + Role Trust Hijacking
c3_idp_poisoning AS (
    SELECT
        p1.principal_id,
        p1.username,
        'TOXIC_COMBO_03_IDP_FEDERATION_POISONING' AS combo_code,
        'CRITICAL' AS severity,
        98.0 AS toxic_score,
        'Can register arbitrary OIDC/SAML providers and update role trust policies' AS hazard_description
    FROM perms p1
    JOIN perms p2 ON p1.principal_id = p2.principal_id
    WHERE (p1.action_pattern IN ('iam:CreateOpenIDConnectProvider', 'iam:CreateSAMLProvider', 'iam:*', '*'))
      AND (p2.action_pattern IN ('iam:UpdateAssumeRolePolicy', 'iam:*', '*'))
),
-- Toxic Combo 4: Network Exposure + Perimeter Demolition
c4_network_demolition AS (
    SELECT
        p1.principal_id,
        p1.username,
        'TOXIC_COMBO_04_PERIMETER_DEMOLITION' AS combo_code,
        'HIGH' AS severity,
        92.0 AS toxic_score,
        'Can authorize 0.0.0.0/0 ingress security groups and attach Internet Gateways' AS hazard_description
    FROM perms p1
    JOIN perms p2 ON p1.principal_id = p2.principal_id
    WHERE (p1.action_pattern IN ('ec2:AuthorizeSecurityGroupIngress', 'ec2:*', '*'))
      AND (p2.action_pattern IN ('ec2:AttachInternetGateway', 'ec2:CreateRoute', 'ec2:*', '*'))
),
-- Toxic Combo 5: Financial Fraud / Double-Sourcing Separation of Duties
c5_financial_sod AS (
    SELECT
        p1.principal_id,
        p1.username,
        'TOXIC_COMBO_05_FINANCIAL_SOD_CONFLICT' AS combo_code,
        'HIGH' AS severity,
        89.0 AS toxic_score,
        'Dual authority over billing modification and compute procurement quotas' AS hazard_description
    FROM perms p1
    JOIN perms p2 ON p1.principal_id = p2.principal_id
    WHERE (p1.action_pattern IN ('aws-portal:ModifyBilling', 'cur:*', '*'))
      AND (p2.action_pattern IN ('ec2:RunInstances', 'servicequotas:RequestServiceQuotaIncrease', '*'))
)
SELECT * FROM c1_trail_destruction
UNION ALL SELECT * FROM c2_ransomware_primitive
UNION ALL SELECT * FROM c3_idp_poisoning
UNION ALL SELECT * FROM c4_network_demolition
UNION ALL SELECT * FROM c5_financial_sod;
