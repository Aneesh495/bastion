-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/graph/privilege_escalation.sql
-- Description: Detection queries for 21 cloud IAM privilege escalation primitives
--              derived from formal graph reachability and effective permissions.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- Catalog of Cloud IAM Privilege Escalation Primitives
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_iam_privilege_escalation_paths AS
WITH perms AS (
    SELECT
        principal_id,
        username,
        action_pattern,
        resource_pattern,
        policy_name,
        inheritance_source
    FROM v_iam_effective_permissions
    WHERE evaluation_verdict = 'EFFECTIVE_ALLOW'
),
-- Primitive 1: iam:CreateAccessKey on other principals
p1_create_access_key AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_01_CREATE_ACCESS_KEY' AS escalation_primitive,
        'CRITICAL' AS severity,
        95.0 AS risk_score,
        'Can generate access keys for other identities including administrators' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:CreateAccessKey', 'iam:*', '*')
),
-- Primitive 2: iam:CreateLoginProfile
p2_create_login_profile AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_02_CREATE_LOGIN_PROFILE' AS escalation_primitive,
        'CRITICAL' AS severity,
        95.0 AS risk_score,
        'Can create console passwords for users that currently lack console access' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:CreateLoginProfile', 'iam:*', '*')
),
-- Primitive 3: iam:UpdateLoginProfile
p3_update_login_profile AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_03_UPDATE_LOGIN_PROFILE' AS escalation_primitive,
        'CRITICAL' AS severity,
        95.0 AS risk_score,
        'Can reset existing console passwords on arbitrary users' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:UpdateLoginProfile', 'iam:*', '*')
),
-- Primitive 4: iam:AttachUserPolicy
p4_attach_user_policy AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_04_ATTACH_USER_POLICY' AS escalation_primitive,
        'CRITICAL' AS severity,
        98.0 AS risk_score,
        'Can attach AdministratorAccess managed policy directly to self' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:AttachUserPolicy', 'iam:*', '*')
),
-- Primitive 5: iam:AttachGroupPolicy
p5_attach_group_policy AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_05_ATTACH_GROUP_POLICY' AS escalation_primitive,
        'HIGH' AS severity,
        90.0 AS risk_score,
        'Can attach managed policies to groups in which they are a member' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:AttachGroupPolicy', 'iam:*', '*')
),
-- Primitive 6: iam:AttachRolePolicy
p6_attach_role_policy AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_06_ATTACH_ROLE_POLICY' AS escalation_primitive,
        'HIGH' AS severity,
        90.0 AS risk_score,
        'Can attach administrator policies to roles they can assume' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:AttachRolePolicy', 'iam:*', '*')
),
-- Primitive 7: iam:PutUserPolicy (inline)
p7_put_user_policy AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_07_PUT_USER_POLICY' AS escalation_primitive,
        'CRITICAL' AS severity,
        98.0 AS risk_score,
        'Can create custom inline policies with wildcard administrator grants' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:PutUserPolicy', 'iam:*', '*')
),
-- Primitive 8: iam:PutGroupPolicy
p8_put_group_policy AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_08_PUT_GROUP_POLICY' AS escalation_primitive,
        'HIGH' AS severity,
        90.0 AS risk_score,
        'Can create custom inline policies on group memberships' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:PutGroupPolicy', 'iam:*', '*')
),
-- Primitive 9: iam:PutRolePolicy
p9_put_role_policy AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_09_PUT_ROLE_POLICY' AS escalation_primitive,
        'HIGH' AS severity,
        90.0 AS risk_score,
        'Can create custom inline policies on assumable roles' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:PutRolePolicy', 'iam:*', '*')
),
-- Primitive 10: iam:AddUserToGroup
p10_add_user_to_group AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_10_ADD_USER_TO_GROUP' AS escalation_primitive,
        'HIGH' AS severity,
        88.0 AS risk_score,
        'Can add arbitrary users to existing high-privileged admin groups' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:AddUserToGroup', 'iam:*', '*')
),
-- Primitive 11: iam:UpdateAssumeRolePolicy
p11_update_assume_role AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_11_UPDATE_ASSUME_ROLE_POLICY' AS escalation_primitive,
        'CRITICAL' AS severity,
        96.0 AS risk_score,
        'Can modify trust policies of administrator roles to allow self-assumption' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:UpdateAssumeRolePolicy', 'iam:*', '*')
),
-- Primitive 12: iam:PassRole + ec2:RunInstances
p12_pass_role_ec2 AS (
    SELECT
        p_pass.principal_id,
        p_pass.username,
        'PRIMITIVE_12_PASSROLE_EC2_RUN' AS escalation_primitive,
        'CRITICAL' AS severity,
        96.0 AS risk_score,
        'Can launch an EC2 instance with an attached high-privilege instance profile' AS description,
        p_pass.policy_name
    FROM perms p_pass
    JOIN perms p_ec2 ON p_pass.principal_id = p_ec2.principal_id
    WHERE (p_pass.action_pattern IN ('iam:PassRole', 'iam:*', '*'))
      AND (p_ec2.action_pattern IN ('ec2:RunInstances', 'ec2:*', '*'))
),
-- Primitive 13: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
p13_pass_role_lambda AS (
    SELECT
        p_pass.principal_id,
        p_pass.username,
        'PRIMITIVE_13_PASSROLE_LAMBDA' AS escalation_primitive,
        'CRITICAL' AS severity,
        96.0 AS risk_score,
        'Can deploy a serverless function with an admin execution role and trigger it' AS description,
        p_pass.policy_name
    FROM perms p_pass
    JOIN perms p_lam ON p_pass.principal_id = p_lam.principal_id
    WHERE (p_pass.action_pattern IN ('iam:PassRole', 'iam:*', '*'))
      AND (p_lam.action_pattern IN ('lambda:CreateFunction', 'lambda:*', '*'))
),
-- Primitive 14: iam:PassRole + glue:CreateDevEndpoint
p14_pass_role_glue AS (
    SELECT
        p_pass.principal_id,
        p_pass.username,
        'PRIMITIVE_14_PASSROLE_GLUE' AS escalation_primitive,
        'HIGH' AS severity,
        85.0 AS risk_score,
        'Can instantiate an AWS Glue DevEndpoint with an admin role' AS description,
        p_pass.policy_name
    FROM perms p_pass
    JOIN perms p_glue ON p_pass.principal_id = p_glue.principal_id
    WHERE (p_pass.action_pattern IN ('iam:PassRole', 'iam:*', '*'))
      AND (p_glue.action_pattern IN ('glue:CreateDevEndpoint', 'glue:*', '*'))
),
-- Primitive 15: iam:PassRole + cloudformation:CreateStack
p15_pass_role_cfn AS (
    SELECT
        p_pass.principal_id,
        p_pass.username,
        'PRIMITIVE_15_PASSROLE_CLOUDFORMATION' AS escalation_primitive,
        'CRITICAL' AS severity,
        94.0 AS risk_score,
        'Can deploy a CloudFormation template with an admin service role' AS description,
        p_pass.policy_name
    FROM perms p_pass
    JOIN perms p_cfn ON p_pass.principal_id = p_cfn.principal_id
    WHERE (p_pass.action_pattern IN ('iam:PassRole', 'iam:*', '*'))
      AND (p_cfn.action_pattern IN ('cloudformation:CreateStack', 'cloudformation:*', '*'))
),
-- Primitive 16: iam:PassRole + datapipeline:CreatePipeline
p16_pass_role_dp AS (
    SELECT
        p_pass.principal_id,
        p_pass.username,
        'PRIMITIVE_16_PASSROLE_DATAPIPELINE' AS escalation_primitive,
        'HIGH' AS severity,
        85.0 AS risk_score,
        'Can instantiate an automated data pipeline with an admin service role' AS description,
        p_pass.policy_name
    FROM perms p_pass
    JOIN perms p_dp ON p_pass.principal_id = p_dp.principal_id
    WHERE (p_pass.action_pattern IN ('iam:PassRole', 'iam:*', '*'))
      AND (p_dp.action_pattern IN ('datapipeline:CreatePipeline', 'datapipeline:*', '*'))
),
-- Primitive 17: lambda:UpdateFunctionCode
p17_lambda_code AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_17_LAMBDA_UPDATE_CODE' AS escalation_primitive,
        'HIGH' AS severity,
        88.0 AS risk_score,
        'Can modify the executable bytecode of a function that runs with admin privileges' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('lambda:UpdateFunctionCode', 'lambda:*', '*')
),
-- Primitive 18: glue:UpdateDevEndpoint
p18_glue_update AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_18_GLUE_UPDATE_ENDPOINT' AS escalation_primitive,
        'HIGH' AS severity,
        85.0 AS risk_score,
        'Can inject custom SSH public keys into existing high-privilege Glue endpoints' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('glue:UpdateDevEndpoint', 'glue:*', '*')
),
-- Primitive 19: iam:SetDefaultPolicyVersion
p19_set_default_version AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_19_SET_DEFAULT_POLICY_VERSION' AS escalation_primitive,
        'HIGH' AS severity,
        90.0 AS risk_score,
        'Can roll back a customer managed policy to an older, over-privileged revision' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:SetDefaultPolicyVersion', 'iam:*', '*')
),
-- Primitive 20: iam:CreatePolicyVersion
p20_create_policy_version AS (
    SELECT
        principal_id,
        username,
        'PRIMITIVE_20_CREATE_POLICY_VERSION' AS escalation_primitive,
        'CRITICAL' AS severity,
        98.0 AS risk_score,
        'Can create a new policy version with wildcard admin permissions' AS description,
        policy_name
    FROM perms
    WHERE action_pattern IN ('iam:CreatePolicyVersion', 'iam:*', '*')
),
-- Primitive 21: sts:AssumeRole
p21_assume_role AS (
    SELECT
        rc.initial_principal_id AS principal_id,
        rc.initial_principal_name AS username,
        'PRIMITIVE_21_TRANSITIVE_ROLE_ASSUMPTION' AS escalation_primitive,
        'MEDIUM' AS severity,
        75.0 AS risk_score,
        'Has transitive role assumption reachability: ' || rc.assumption_path AS description,
        'ROLE_TRUST_POLICY' AS policy_name
    FROM v_iam_role_assumption_chains rc
)
-- Union all 21 primitives
SELECT * FROM p1_create_access_key
UNION ALL SELECT * FROM p2_create_login_profile
UNION ALL SELECT * FROM p3_update_login_profile
UNION ALL SELECT * FROM p4_attach_user_policy
UNION ALL SELECT * FROM p5_attach_group_policy
UNION ALL SELECT * FROM p6_attach_role_policy
UNION ALL SELECT * FROM p7_put_user_policy
UNION ALL SELECT * FROM p8_put_group_policy
UNION ALL SELECT * FROM p9_put_role_policy
UNION ALL SELECT * FROM p10_add_user_to_group
UNION ALL SELECT * FROM p11_update_assume_role
UNION ALL SELECT * FROM p12_pass_role_ec2
UNION ALL SELECT * FROM p13_pass_role_lambda
UNION ALL SELECT * FROM p14_pass_role_glue
UNION ALL SELECT * FROM p15_pass_role_cfn
UNION ALL SELECT * FROM p16_pass_role_dp
UNION ALL SELECT * FROM p17_lambda_code
UNION ALL SELECT * FROM p18_glue_update
UNION ALL SELECT * FROM p19_set_default_version
UNION ALL SELECT * FROM p20_create_policy_version
UNION ALL SELECT * FROM p21_assume_role;
