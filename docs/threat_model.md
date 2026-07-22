# Bastion Threat Model and Adversary Analysis

## 1. Scope and Objective

This threat model outlines the threat profiles, attack surfaces, adversarial tactics, and defensive security guarantees evaluated by Bastion. The system models enterprise hybrid cloud environments spanning virtual private clouds (VPCs), multi-tier organizational units, Kubernetes worker nodes, serverless function runtimes, relational database clusters, and cloud identity providers.

## 2. Adversary Personas and Profiles

| Adversary Identifier | Threat Actor Group | Motivations | Primary Tactics |
|:---|:---|:---|:---|
| `act-apt29` | APT29 (Cozy Bear) | Espionage, long-term intelligence gathering | Web ingress exploitation, low-jitter periodic C2 beaconing, DNS tunneling, multi-hop lateral pivots |
| `act-fin7` | FIN7 (Carbanak) | Financial gain, payment card theft | Memory credential scraping (LSASS), privilege escalation via IAM policy version manipulation |
| `act-wizard` | Wizard Spider (Conti / BlackCat) | Extortion, operational disruption | Bulk file encryption, audit log deletion, volume shadow copy purge, ransom payload delivery |
| `act-insider` | Rogue Contractor / Privileged User | Data exfiltration, sabotage | Separation of Duties bypass, toxic permission combinations, dormant account resurrection |

## 3. Attack Surfaces and Mitigation Matrix

```
       Attacking Vector                   Bastion Defense Mechanism
+-----------------------------+       +-------------------------------+
| Web Application Ingress     | ----> | Rule BST-R-0104: Path/SQLi    |
| (T1190 Exploit Ingress)     |       | HTTP access log inspection    |
+-----------------------------+       +-------------------------------+
| Reverse Interactive Shell   | ----> | Rule BST-R-0202: Socket Shell |
| (T1059.004 Process Pipeline)|       | Process tree execution monitor|
+-----------------------------+       +-------------------------------+
| Cloud IAM Escalation        | ----> | Kernel v_iam_privilege_esc    |
| (21 Cloud IAM Vectors)      |       | Recursive policy statement CTE|
+-----------------------------+       +-------------------------------+
| Lateral Network Pivots      | ----> | Kernel v_active_lateral_paths |
| (DMZ to Crown Jewels)       |       | VPC flow reachability graph   |
+-----------------------------+       +-------------------------------+
| Periodic C2 Beaconing       | ----> | Kernel v_c2_beaconing         |
| (Low-Jitter Time-Series)    |       | Delta coefficient of variation|
+-----------------------------+       +-------------------------------+
| Audit Ledger Tampering      | ----> | Kernel v_audit_health_summary |
| (CloudTrail log deletion)   |       | Cryptographic SHA-256 chain   |
+-----------------------------+       +-------------------------------+
```

### 3.1 Web Ingress Exploitation (T1190)
- **Threat Vector**: Ingress HTTP requests targeting web applications containing path traversal (`/../../../../etc/passwd`) or SQL injection payload tokens (`UNION SELECT ...`).
- **Defensive Kernel**: `v_rule_t1190_web_application_exploit` inspects normalized request URIs and query parameters within HTTP access logs, joining compute asset metadata to generate HIGH-severity detection findings.

### 3.2 Interactive Reverse Shell Pipeline (T1059.004)
- **Threat Vector**: Spawned shell process (`/bin/sh`, `/bin/bash`, `powershell.exe`) with command line arguments containing socket redirects (`/dev/tcp/...`, `nc -e`, `IEX (New-Object Net.WebClient)`).
- **Defensive Kernel**: `v_rule_t1059_004_unix_shell_reverse_connection` evaluates process execution telemetry, checking parent-child process ancestry and elevated privileges.

### 3.3 Cloud IAM Privilege Escalation (T1078.004 / T1098)
- **Threat Vector**: Adversary attaches administrative policies (`iam:AttachUserPolicy`, `iam:PutUserPolicy`), creates rogue access keys, or creates a new policy version with wildcard permissions.
- **Defensive Kernel**: `v_iam_privilege_escalation_paths` dynamically parses effective IAM permissions, checking for 21 established escalation primitives across AWS IAM, GCP IAM, and Azure RBAC paradigms.

### 3.4 Multi-Hop Lateral Network Pivoting (T1021)
- **Threat Vector**: Direct unauthorized network communication from internet-facing DMZ subnets into Tier 1 isolated databases and settlement systems.
- **Defensive Kernel**: `v_active_lateral_attack_paths` executes recursive reachability analysis across network flow logs and topological graph edges, discovering multi-hop attack routes and flagging paths that violate zone isolation invariants.

### 3.5 Periodic Command and Control Beaconing (T1071 / T1573)
- **Threat Vector**: Automated implant communicating with external C2 servers on regular intervals with minimal jitter.
- **Defensive Kernel**: `v_c2_beaconing_candidates` computes inter-arrival time deltas $\Delta t_i$ across successive network flow sessions, calculating the coefficient of variation ($CV = \sigma / \mu$). Flows exhibiting $CV \le 0.15$ with at least 5 observations are classified as high-confidence beaconing signals.

### 3.6 Data Exfiltration (T1048 / T1041)
- **Threat Vector**: Large volume outbound data egress over short durations, or exfiltration disguised as base64-encoded subdomains in DNS queries.
- **Defensive Kernel**: `v_asymmetric_egress_flows` evaluates destination concentration ratios and detects off-hours volume spikes. Concurrently, `v_dga_candidate_domains` evaluates Shannon lexical entropy ($H > 3.5$) on DNS query hostnames.

### 3.7 Cryptographic Audit Trail Manipulation (T1562.002)
- **Threat Vector**: Adversary attempts to clear CloudTrail logs or delete forensic records.
- **Defensive Kernel**: `v_audit_recomputed_hash_chain` recomputes the SHA-256 block hash for every audit record:
  $$H_i = \text{SHA256}(i \mathbin{\Vert} \text{actor} \mathbin{\Vert} \text{action} \mathbin{\Vert} \text{entity} \mathbin{\Vert} \text{before} \mathbin{\Vert} \text{after} \mathbin{\Vert} \text{nonce} \mathbin{\Vert} H_{i-1})$$
  Any mutated entry breaks the hash pointer to the subsequent block, immediately surfacing in `v_forensic_tamper_discrepancies`.
