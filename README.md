```
  ____             _   _             
 | __ )  __ _ ___| |_(_) ___  _ __  
 |  _ \ / _` / __| __| |/ _ \| '_ \ 
 | |_) | (_| \__ \ |_| | (_) | | | |
 |____/ \__,_|___/\__|_|\___/|_| |_|
```

# Bastion: Autonomous Zero-Trust Identity Graph and Real-Time Threat Detection Kernel in ANSI SQL

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Engine](https://img.shields.io/badge/engine-DuckDB%20%7C%20SQLite-yellowgreen.svg)](#relational-engine)
[![Tests](https://img.shields.io/badge/tests-4%20suites%20%2F%2030%2B%20assertions%20passing-brightgreen.svg)](#verification)
[![Dialect](https://img.shields.io/badge/sql-ANSI%20SQL%20%7C%20PostgreSQL-orange.svg)](#architecture)

Bastion is an autonomous Zero-Trust Identity Graph, real-time threat detection engine, lateral movement graph traversal kernel, and forensic telemetry ledger built entirely in declarative ANSI SQL. It eliminates external graph libraries, statistical frameworks, and procedural pipelines by embedding graph theory, statistical inference, state machine automata, and cryptographic hashing directly into relational query calculus.

```
                           +----------------------------------------+
                           |       Enterprise Telemetry Ingress     |
                           |  (VPC Flow, CloudTrail, DNS, Processes)|
                           +-------------------+--------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |       Core Relational Data Catalog     |
                           |   (Entities, Principals, Graph Nodes)  |
                           +-------------------+--------------------+
                                               |
                    +--------------------------+--------------------------+
                    |                          |                          |
                    v                          v                          v
       +-----------------------+  +-----------------------+  +-----------------------+
       |   Relational Graph    |  |  Statistical Anomaly  |  |  MITRE ATT&CK Catalog |
       |     Traversal CTEs    |  |    Inference Engine   |  |   12 Tactics / Rules  |
       | (Roles, Blast Radius) |  |  (C2, DGA, Travel)    |  |  (Brute Force, Shell) |
       +-----------+-----------+  +-----------+-----------+  +-----------+-----------+
                    |                          |                          |
                    +--------------------------+--------------------------+
                                               |
                                               v
                           +----------------------------------------+
                           | Unified Multi-Tactic Detection Engine  |
                           |    (Suppression & Campaign Scoring)    |
                           +-------------------+--------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |    Incident DFA Lifecycle & Playbook   |
                           |  (State Machine & Auto-Remediation)    |
                           +-------------------+--------------------+
                                               |
                                               v
                           +----------------------------------------+
                           |  Cryptographic SHA-256 Audit Ledger    |
                           |     (Tamper-Evident Hash Chain)        |
                           +-------------------+--------------------+
```

---

## Key Capabilities

### 1. Pure SQL Recursive Graph Traversal
- **Transitive IAM Role Chains**: Evaluates arbitrary-depth role assumption paths ($A \to B \to C$) using recursive Common Table Expressions (CTEs).
- **21 Cloud IAM Privilege Escalation Primitives**: Exhaustive pattern-matching engine detecting unauthorized permission attachment, policy version reversion, lambda execution role escalation, and user credential injection across AWS IAM, GCP IAM, and Azure RBAC paradigms.
- **Separation of Duties (Toxic Combinations)**: Bipartite conflict detection identifying mutually exclusive administrative capabilities (e.g. KMS key destruction combined with CloudTrail log deletion).
- **Multi-Hop Lateral Attack Paths**: Finds reachable routes from internet-facing DMZ subnets into Tier 1 Crown Jewel database clusters with string-based cycle elimination guards.
- **Defensive Choke Points & Centrality**: Computes intermediate transit frequency and betweenness centrality proxies to identify high-leverage defensive isolation targets.
- **Compromise Blast Radius Valuation**: Calculates transitive asset reachability and cumulative criticality exposure from compromised seed nodes.

### 2. Statistical Anomaly Inference in Relational Calculus
- **Periodic C2 Beaconing Detection**: Computes packet inter-arrival time deltas $\Delta t_i = t_i - t_{i-1}$, sample mean $\mu_{\Delta t}$, and sample variance $s^2$ using Welford's algorithm. Evaluates coefficient of variation ($CV = \sigma / \mu \le 0.15$) to detect low-jitter automated implants.
- **Impossible Geodesic Travel Velocity**: Implements the spherical Haversine formula directly in SQL to calculate geodesic distance between successive authentications. Flags velocities exceeding 1,000 km/h as impossible travel anomalies.
- **Domain Generation Algorithm (DGA) Entropy**: Calculates lexical Shannon entropy ($H \ge 3.5$) and consonant-to-vowel distribution ratios across second-level domain strings to uncover synthetic C2 domains.
- **Asymmetric Egress Volume Outliers**: Windowed Z-score anomaly modeling over VPC flow volume to detect high-velocity data exfiltration.
- **Distributed Password Spray Clustering**: Identifies multi-source coordinated authentication failures targeting disparate enterprise identities.
- **Domain Typosquatting & Homoglyphs**: Calculates edit distance heuristics to identify corporate brand impersonation lookups.

### 3. MITRE ATT&CK Multi-Tactic Detection Engine
- Comprehensive coverage across 12 MITRE ATT&CK enterprise tactics:
  - Initial Access (`TA0001`): Console logins without MFA, Tor ingress, public exploit patterns
  - Execution (`TA0002`): Interactive reverse shell sockets, PowerShell execution policy bypasses
  - Persistence (`TA0003`): Rogue IAM access keys, SSH authorized_keys modifications
  - Privilege Escalation (`TA0004`): Elevated policy attachments, sudo spawning
  - Defense Evasion (`TA0005`): Audit logging termination, log clearing commands
  - Credential Access (`TA0006`): Memory dumping (LSASS), kerberoasting patterns
  - Discovery (`TA0007`): Internal subnet port scanning, cloud infrastructure discovery
  - Lateral Movement (`TA0008`): Direct DMZ-to-database pivots, pass-the-hash patterns
  - Collection (`TA0009`): Bulk S3 bucket downloads, sensitive table queries
  - Exfiltration (`TA0010`): High-volume asymmetric outbound egress, DNS tunneling
  - Command and Control (`TA0011`): Confirmed C2 indicator matching, DGA query bursts
  - Impact (`TA0040`): Rapid file modification bursts, ransomware extensions
- **Multi-Stage Campaign Progression**: Unifies detections into entity kill-chain stages (Stage 1 Initial Probe through Stage 4 Full Kill-Chain Breach).
- **Dynamic Alert Suppression**: Contextual suppression filters that account for active maintenance windows and entity attributes without dropping raw forensic signals.

### 4. Incident Lifecycle DFA and Automated Response Synthesis
- **Deterministic Finite Automaton**: Enforces strict state transitions (`DETECTED` $\to$ `TRIAGED` $\to$ `CONTAINED` $\to$ `REMEDIATED` $\to$ `RESOLVED`). Guard conditions block illegal shortcuts.
- **Automated Playbook Synthesis**: Generates idempotent SQL remediation statements (`UPDATE core_compute_assets SET is_quarantined = TRUE...`, `REVOKE ...`) based on observed tactics and entity types.
- **Chronological Timeline Builder**: Reconstructs complete multi-signal attack timelines with calculated adversary dwell time.

### 5. Cryptographic SHA-256 Audit Ledger
- In-database tamper-evident audit ledger chaining:
  $$H_i = \text{SHA256}(i \mathbin{\Vert} \text{timestamp} \mathbin{\Vert} \text{actor} \mathbin{\Vert} \text{action} \mathbin{\Vert} \text{payload} \mathbin{\Vert} H_{i-1})$$
- Continuous tamper detection view `v_forensic_tamper_discrepancies` comparing stored hash values with recomputed SHA-256 block chains to verify data integrity.

---

## Directory Architecture

```
bastion/
├── bin/
│   └── bastion                    # Executable CLI entrypoint
├── bastion/                       # Python database harness and visualizer
│   ├── engine.py                  # Multi-engine abstraction (DuckDB CLI / SQLite)
│   ├── cli.py                     # CLI router and auto-initialization pipeline
│   ├── generator.py               # Synthetic topology and telemetry generator
│   └── visualizer.py              # ANSI terminal formatting and tables
├── sql/
│   ├── schema/                    # 8 DDL schema definition modules
│   │   ├── 01_core.sql            # Organizations, accounts, assets, identities
│   │   ├── 02_telemetry.sql       # VPC flows, auth logs, CloudTrail, DNS, process events
│   │   ├── 03_graph.sql           # Graph nodes, edges, and topology matrices
│   │   ├── 04_intel.sql           # MITRE taxonomy and threat intel IOCs
│   │   ├── 05_analytics.sql       # Statistical anomaly baselines
│   │   ├── 06_detection.sql       # Detection rule registry and alert schemas
│   │   ├── 07_incident.sql        # DFA state machine, incidents, and playbooks
│   │   └── 08_audit.sql           # Cryptographic SHA-256 audit ledger
│   ├── functions/                 # Mathematical and string kernel functions
│   ├── graph/                     # 6 Relational graph traversal views (recursive CTEs)
│   ├── analytics/                 # 5 Statistical anomaly detection models
│   ├── entity_resolution/         # 3 Identity clustering and typosquatting views
│   ├── rules/                     # 13 MITRE ATT&CK detection modules and orchestrator
│   ├── incident/                  # 4 Incident correlation, timeline, and playbook views
│   ├── audit/                     # 2 Cryptographic hash chain verification views
│   └── seeds/                     # 6 Comprehensive enterprise synthetic datasets
├── tests/                         # Relational verification test suites
│   ├── unit_tests.sql             # Mathematical, string, and CIDR unit tests
│   ├── graph_tests.sql            # IAM, lateral movement, and blast radius tests
│   ├── analytics_tests.sql        # C2 beaconing, DGA, and impossible travel tests
│   └── integration_tests.sql      # End-to-end APT29 campaign and audit tests
├── bench/                         # Benchmarks and execution plan diagnostics
│   ├── benchmarks.sql             # Compute latency benchmarks across kernels
│   └── explain_plans.sql          # Relational EXPLAIN execution plan analysis
├── docs/                          # Detailed technical documentation
│   ├── architecture.md            # Comprehensive architecture specification
│   ├── threat_model.md            # Adversary analysis and attack surface matrix
│   ├── graph_theory.md            # Graph algorithms and recursive CTE treatise
│   ├── statistical_methods.md     # Mathematical foundations of anomaly models
│   └── verification_guide.md      # Reproduction and testing runbook
├── pyproject.toml                 # Packaging specification
└── Makefile                       # Build, verification, and benchmark automation
```

---

## Quickstart

### Prerequisites
- Python 3.9+
- DuckDB CLI binary (`duckdb`) or SQLite3
- Unix utilities (`make`, `grep`, `git`)

### 1. Clone and Run Verification Test Suite
```bash
git clone https://github.com/Aneesh495/bastion.git
cd bastion
make test
```

### 2. Execute MITRE ATT&CK Threat Detection Scan
Scan the enterprise telemetry corpus across all 12 MITRE tactics:
```bash
./bin/bastion scan
```

### 3. Run Relational Graph Traversal and Attack Paths
Evaluate transitive role assumptions, lateral movement paths, and choke points:
```bash
./bin/bastion graph
```

### 4. Verify Cryptographic SHA-256 Audit Ledger
Verify the integrity of the forensic ledger hash chain:
```bash
./bin/bastion audit
```

### 5. Run Execution Benchmarks
Benchmark query performance across analytical and graph kernels:
```bash
./bin/bastion bench
```

---

## Execution Benchmarks

Benchmarked using DuckDB columnar relational engine on macOS (Apple M-series):

| Benchmark Identifier | Workload Description | Engine Category | Output Cardinality | Latency Target | Status |
|:---|:---|:---|:---|:---|:---|
| `BENCH-01` | Recursive Lateral Movement Traversal | Graph Kernel (Recursive CTE) | 8 paths | < 50 ms | **PASS** |
| `BENCH-02` | Cloud IAM Privilege Escalation Matrix | IAM Graph (21 Primitives) | 72 paths | < 50 ms | **PASS** |
| `BENCH-03` | C2 Periodic Beaconing Coefficient of Variation | Time-Series Analytics | 1 candidate | < 25 ms | **PASS** |
| `BENCH-04` | Multi-Tactic Detection Orchestrator Union | Detection Engine | 24 alerts | < 100 ms | **PASS** |
| `BENCH-05` | SHA-256 Cryptographic Hash Chain Audit | Cryptographic Integrity | 3 blocks | < 10 ms | **PASS** |

---

## Architecture and Design Documentation

Detailed engineering treatises are located in the `docs/` directory:
- [Architecture Specification](docs/architecture.md): Subsystem decomposition and data flow lineages.
- [Threat Model and Adversary Analysis](docs/threat_model.md): Detailed attacker profiles (APT29, FIN7, Wizard Spider).
- [Graph Theory Treatise](docs/graph_theory.md): Mathematical formulations of recursive reachability, cycle elimination, and betweenness centrality.
- [Statistical Methods Manual](docs/statistical_methods.md): Formulations of Welford variance, Holt-Winters EWMA, C2 beaconing CV, and Haversine geodesic velocity.
- [Verification Guide](docs/verification_guide.md): Comprehensive reproduction steps and diagnostic runbooks.

---

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
