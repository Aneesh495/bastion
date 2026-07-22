# Bastion Verification and Reproduction Guide

This guide details the procedure for validating Bastion on macOS or Linux systems. Every component is designed to run deterministically with zero manual configuration.

## 1. Prerequisites

- Python 3.9+
- DuckDB CLI binary (`duckdb`) or SQLite3
- Standard Unix utilities (`make`, `grep`, `git`)

## 2. Fast-Path Verification

Execute the complete test suite directly using `make`:

```bash
make test
```

Expected output:
```
[*] Applying 45 SQL schema, kernel, and detection modules...
[+] Schema and kernel initialization completed successfully (45 modules).

  ____             _   _             
 | __ )  __ _ ___| |_(_) ___  _ __  
 |  _ \ / _` / __| __| |/ _ \| '_ \ 
 | |_) | (_| \__ \ |_| | (_) | | | |
 |____/ \__,_|___/\__|_|\___/|_| |_|
 Autonomous Zero-Trust Security Kernel

[*] Executing 4 SQL verification test suites...

  [+] PASS: tests/analytics_tests.sql (7 assertions, 277.9 ms)
  [+] PASS: tests/graph_tests.sql (7 assertions, 306.4 ms)
  [+] PASS: tests/integration_tests.sql (7 assertions, 316.0 ms)
  [+] PASS: tests/unit_tests.sql (9 assertions, 330.9 ms)

Verification Results: 4 test suites passed, 0 failed.
```

## 3. Subsystem CLI Commands

### 3.1 MITRE ATT&CK Threat Detection Scan
Scan synthetic enterprise telemetry across all 12 MITRE tactics:

```bash
./bin/bastion scan
```

Expected findings include:
- `BST-R-0104`: Web Ingress Application Attack (SQLi / path traversal)
- `BST-R-0202`: Interactive Reverse Shell Command Pipeline
- `BST-R-0401`: Privileged Policy Attachment
- `BST-R-0502`: Audit Log Deletion Command
- `BST-R-0601`: LSASS Memory Credential Dumping
- `BST-R-0801`: Unauthorized DMZ to Crown Jewel Pivot
- `BST-R-1101`: Periodic C2 Beaconing Communication
- Campaign progression: Entity `ast-web-01` categorized as `STAGE_4_FULL_KILL_CHAIN_BREACH`.

### 3.2 Relational Graph Traversal and Attack Paths
Evaluate role assumption chains, lateral reachability, and choke points:

```bash
./bin/bastion graph
```

Outputs 6 graph kernel result tables:
1. `v_iam_role_assumption_chains`: Recursive role assumption paths (`usr-devops-01 -> DevOpsRole -> BreakGlassAdmin`).
2. `v_iam_privilege_escalation_paths`: 21 cloud IAM escalation vectors identified.
3. `v_iam_toxic_combinations`: Separation of Duties conflict pairs evaluated.
4. `v_active_lateral_attack_paths`: Cycle-free multi-hop lateral routes reaching Tier 1 Crown Jewels.
5. `v_network_choke_points`: Intermediate transit betweenness centrality ratios.
6. `v_asset_compromise_blast_radius`: Transitive compromise exposure (`CATASTROPHIC_TIER_1_EXPOSURE`).

### 3.3 Cryptographic Audit Ledger Integrity
Verify the immutable SHA-256 block ledger:

```bash
./bin/bastion audit
```

Confirms `ledger_integrity_status = LEDGER_INTEGRITY_VERIFIED_CLEAN` and `tampered_block_count = 0`.

### 3.4 Workload Benchmarking and Execution Plans
Run query latency benchmarks and execution plan diagnostics:

```bash
./bin/bastion bench
```

Executes 5 critical workloads with latency targets under 50 ms.

## 4. Lint and Formatting Invariants

Ensure strict compliance with coding guidelines (including zero em dashes):

```bash
make check-no-em-dash
```

This enforces that no em dash unicode characters exist anywhere in code, comments, or documentation files.
