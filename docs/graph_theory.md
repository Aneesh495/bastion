# Relational Graph Theory and Traversal Kernels

Bastion executes complex graph algorithms over relational schemas without relying on specialized external graph engines. By modeling graph topology in ANSI SQL and leveraging recursive Common Table Expressions (CTEs), Bastion computes transitive reachability, shortest paths, cycle-free attack routes, betweenness centrality, and compromise blast radius.

## 1. Graph Data Model in Relational Calculus

A directed graph $G = (V, E)$ is represented as two relational tables:
- **Vertices $V$**: `graph_nodes` storing entity identifiers, node types, account IDs, and criticality tiers.
- **Edges $E$**: `graph_edges` storing directed transitions $(u, v) \in V \times V$, edge types (`NETWORK_INGRESS`, `CAN_ASSUME_ROLE`, `HAS_PERMISSION_ON`), transition costs, and port protocols.

```
       [ Node: ast-edge-01 ]
                 |
                 | (NETWORK_INGRESS:8080)
                 v
       [ Node: ast-web-01 ]
                 |
                 | (OBSERVED_NETWORK_FLOW:22)
                 v
       [ Node: ast-db-01 (Crown Jewel) ]
```

## 2. Recursive Path Traversal with Cycle Elimination

Finding reachable paths from source node $s$ to destination node $t$ is expressed as a least fixed-point computation:

$$\text{Paths}_0 = \{ (u, v, [u, v], 1) \mid (u, v) \in E, \text{type}(u) = \text{'DMZ'} \}$$
$$\text{Paths}_{k+1} = \text{Paths}_k \cup \{ (u, w, p \mathbin{\Vert} [w], k+1) \mid (u, v, p, k) \in \text{Paths}_k, (v, w) \in E, w \notin p \}$$

In ANSI SQL, this is implemented as:

```sql
WITH RECURSIVE attack_paths AS (
    -- Base case: 1-hop outbound transitions from DMZ assets
    SELECT
        e.source_asset_id AS origin_asset_id,
        e.source_hostname AS origin_hostname,
        e.target_asset_id AS current_asset_id,
        e.target_hostname AS current_hostname,
        e.target_is_crown_jewel,
        1 AS hop_count,
        e.base_hop_cost AS cumulative_cost,
        e.source_hostname || ' -> ' || e.target_hostname AS full_path_trace
    FROM v_lateral_movement_edges e
    WHERE e.source_zone = 'DMZ'

    UNION ALL

    -- Recursive step: extend traversal to adjacent connected targets
    SELECT
        ap.origin_asset_id,
        ap.origin_hostname,
        e.target_asset_id AS current_asset_id,
        e.target_hostname AS current_hostname,
        e.target_is_crown_jewel,
        ap.hop_count + 1 AS hop_count,
        ap.cumulative_cost + e.base_hop_cost AS cumulative_cost,
        ap.full_path_trace || ' -> ' || e.target_hostname AS full_path_trace
    FROM attack_paths ap
    JOIN v_lateral_movement_edges e ON ap.current_asset_id = e.source_asset_id
    WHERE ap.hop_count < 5
      AND ap.target_is_crown_jewel = FALSE
      -- Cycle guard: prevent revisiting any previously visited host
      AND INSTR(ap.full_path_trace, e.target_hostname) = 0
)
SELECT * FROM attack_paths;
```

### Invariants Guaranteed
1. **Termination Guarantee**: Bound by `hop_count < 5`, ensuring finite execution depth even on cyclic topologies.
2. **Cycle Prevention**: The string predicate `INSTR(ap.full_path_trace, e.target_hostname) = 0` guarantees that no intermediate node is visited more than once per path.
3. **Crown Jewel Short-Circuit**: Traversal terminates upon reaching an asset marked `target_is_crown_jewel = TRUE`.

## 3. Cloud IAM Privilege Escalation Primitives

Bastion evaluates 21 distinct cloud IAM privilege escalation vectors across effective permission graphs:

| Primitive Code | Description | Key Permissions Required | Risk Score |
|:---|:---|:---|:---|
| `PRIMITIVE_01_CREATE_ACCESS_KEY` | Create secondary credentials for target account | `iam:CreateAccessKey` | 95.0 |
| `PRIMITIVE_02_CREATE_LOGIN_PROFILE` | Create web console login profile for API user | `iam:CreateLoginProfile` | 95.0 |
| `PRIMITIVE_03_UPDATE_LOGIN_PROFILE` | Reset console password on target account | `iam:UpdateLoginProfile` | 95.0 |
| `PRIMITIVE_04_ATTACH_USER_POLICY` | Directly attach administrator policy to self | `iam:AttachUserPolicy` | 98.0 |
| `PRIMITIVE_05_ATTACH_GROUP_POLICY` | Attach administrator policy to member group | `iam:AttachGroupPolicy` | 90.0 |
| `PRIMITIVE_06_ATTACH_ROLE_POLICY` | Attach administrator policy to assumable role | `iam:AttachRolePolicy` | 90.0 |
| `PRIMITIVE_07_PUT_USER_POLICY` | Inject inline administrator policy to self | `iam:PutUserPolicy` | 98.0 |
| `PRIMITIVE_08_PUT_GROUP_POLICY` | Inject inline policy into parent group | `iam:PutGroupPolicy` | 90.0 |
| `PRIMITIVE_09_PUT_ROLE_POLICY` | Inject inline policy into assumable role | `iam:PutRolePolicy` | 90.0 |
| `PRIMITIVE_10_ADD_USER_TO_GROUP` | Add unprivileged identity to admin group | `iam:AddUserToGroup` | 92.0 |
| `PRIMITIVE_11_UPDATE_ASSUME_ROLE_POLICY` | Alter role trust policy to allow self-assumption | `iam:UpdateAssumeRolePolicy` | 96.0 |
| `PRIMITIVE_12_CREATE_POLICY_VERSION` | Create new permissive version of managed policy | `iam:CreatePolicyVersion` | 96.0 |
| `PRIMITIVE_13_SET_DEFAULT_POLICY_VERSION` | Revert to previous overprivileged policy version | `iam:SetDefaultPolicyVersion` | 88.0 |
| `PRIMITIVE_14_PASS_ROLE_EC2` | Pass administrative role to newly launched instance | `iam:PassRole`, `ec2:RunInstances` | 94.0 |
| `PRIMITIVE_15_PASS_ROLE_LAMBDA` | Pass administrative role to serverless function | `iam:PassRole`, `lambda:CreateFunction` | 94.0 |
| `PRIMITIVE_16_PASS_ROLE_GLUE` | Pass administrative role to ETL data pipeline | `iam:PassRole`, `glue:CreateDevEndpoint` | 90.0 |
| `PRIMITIVE_17_PASS_ROLE_SAGEMAKER` | Pass administrative role to ML notebook instance | `iam:PassRole`, `sagemaker:CreateNotebook` | 90.0 |
| `PRIMITIVE_18_PASS_ROLE_CODEBUILD` | Pass administrative role to CI/CD build project | `iam:PassRole`, `codebuild:CreateProject` | 90.0 |
| `PRIMITIVE_19_PASS_ROLE_ECS` | Pass administrative role to container task definition | `iam:PassRole`, `ecs:RegisterTaskDefinition` | 92.0 |
| `PRIMITIVE_20_UPDATE_CREDENTIALS` | Upload secondary SSH key to target identity | `iam:UploadSSHPublicKey` | 85.0 |
| `PRIMITIVE_21_DEACTIVATE_MFA` | Disable MFA enforcement device on target identity | `iam:DeactivateMFADevice` | 99.0 |

## 4. Separation of Duties (Toxic Combinations)

Toxic combinations represent hazardous permission pairings that, when held by a single identity, violate fundamental governance principles:

1. **Log Destruction Hazard**: `cloudtrail:StopLogging` combined with `s3:DeleteBucket`.
2. **Ransomware Encryption Hazard**: `kms:ScheduleKeyDeletion` combined with `kms:PutKeyPolicy`.
3. **IdP Federation Hijack**: `iam:CreateSAMLProvider` combined with `iam:CreateRole`.

Bastion evaluates toxic combinations as a bipartite matching over effective permissions in `v_iam_toxic_combinations`.

## 5. Betweenness Centrality and Defensive Choke Points

Betweenness centrality measures how frequently a node $v$ sits on the shortest attack path between all pairs of nodes $(s, t)$:

$$C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$

Bastion computes this in `v_network_choke_points` by aggregating attack path string traces:

```sql
SELECT
    intermediate_asset_id AS asset_id,
    intermediate_hostname AS hostname,
    COUNT(DISTINCT full_path_trace) AS total_paths_traversed,
    COUNT(DISTINCT CASE WHEN breaches_crown_jewel = TRUE THEN full_path_trace END) AS crown_jewel_paths_traversed
FROM path_nodes
GROUP BY intermediate_asset_id, intermediate_hostname;
```

Assets exhibiting high betweenness ratios represent defensive choke points where network isolation yields the highest containment efficiency.

## 6. Transitive Asset Compromise Blast Radius

The blast radius kernel `v_asset_compromise_blast_radius` computes the transitive reach of a compromised seed asset $s$:
- $\text{Total Exposed Assets}: |\{ u \in V \mid s \rightsquigarrow u \}|$
- $\text{Exposed Crown Jewels}: |\{ u \in V_{\text{critical}} \mid s \rightsquigarrow u \}|$
- $\text{Cumulative Criticality Exposure}: \sum_{u} \text{criticality\_score}(u)$

If $\text{Exposed Crown Jewels} > 0$, the blast radius is classified as `CATASTROPHIC_TIER_1_EXPOSURE`, directly triggering automated containment synthesis.
