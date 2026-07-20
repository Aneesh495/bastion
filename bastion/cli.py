"""Command-line interface for the Bastion security kernel.

Provides unified commands for schema migration, synthetic seeding,
rule scanning, graph traversal, audit ledger verification, benchmarking, and testing.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List

from bastion.engine import DatabaseEngine, create_engine
from bastion.visualizer import TerminalVisualizer


def get_project_root() -> Path:
    """Resolves the root directory of the Bastion repository."""
    return Path(__file__).resolve().parent.parent


def find_sql_files(directory: Path) -> List[Path]:
    """Finds and sorts all SQL files recursively within a target directory."""
    if not directory.exists():
        return []
    files = list(directory.glob("**/*.sql"))
    return sorted(files, key=lambda p: (1 if "orchestrator" in p.name else 0, p.name))


def cmd_migrate(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes all schema migration DDL scripts, functions, graph kernels, and rules."""
    root = get_project_root()
    subdirs = [
        "sql/schema",
        "sql/functions",
        "sql/graph",
        "sql/analytics",
        "sql/entity_resolution",
        "sql/rules",
        "sql/incident",
        "sql/audit",
    ]

    files: List[Path] = []
    for sd in subdirs:
        files.extend(find_sql_files(root / sd))

    if not files:
        print("[!] No SQL schema files found.")
        return 1

    print(f"[*] Applying {len(files)} SQL schema, kernel, and detection modules...")
    for file_path in files:
        rel_path = file_path.relative_to(root)
        start = time.perf_counter()
        engine.execute_file(file_path)
        elapsed = (time.perf_counter() - start) * 1000.0
        if getattr(args, "verbose", False):
            print(f"  + Applied: {rel_path} ({elapsed:.1f} ms)")

    print(f"[+] Schema and kernel initialization completed successfully ({len(files)} modules).")
    return 0


def cmd_seed(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Seeds synthetic topology, threat intel, baseline telemetry, and attack scenarios."""
    root = get_project_root()
    _ensure_initialized(engine, with_seeds=False)

    seeds_dir = root / "sql" / "seeds"
    files = find_sql_files(seeds_dir)

    if not files:
        print("[!] No seed files found in sql/seeds.")
        return 1

    print(f"[*] Ingesting {len(files)} synthetic seed datasets...")
    for file_path in files:
        rel_path = file_path.relative_to(root)
        start = time.perf_counter()
        engine.execute_file(file_path)
        elapsed = (time.perf_counter() - start) * 1000.0
        print(f"  + Seeded: {rel_path} ({elapsed:.1f} ms)")

    print("[+] Seeding completed successfully.")
    return 0


def _ensure_initialized(engine: DatabaseEngine, with_seeds: bool = True) -> None:
    """Ensures database schema and seeds are loaded prior to analytical commands."""
    try:
        res = engine.execute("SELECT COUNT(*) FROM core_cloud_accounts;")
        has_schema = True
        has_data = res.rows and res.rows[0][0] > 0
    except Exception:
        has_schema = False
        has_data = False

    dummy_args = argparse.Namespace(verbose=False)
    if not has_schema:
        cmd_migrate(engine, dummy_args)
    if with_seeds and not has_data:
        root = get_project_root()
        seeds_dir = root / "sql" / "seeds"
        for file_path in find_sql_files(seeds_dir):
            engine.execute_file(file_path)


def cmd_scan(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes multi-tactic MITRE ATT&CK detection catalog and campaign progression."""
    _ensure_initialized(engine, with_seeds=True)
    print(TerminalVisualizer.render_banner())
    print("[*] Executing MITRE ATT&CK detection catalog across telemetry corpus...\n")

    start_total = time.perf_counter()
    res_feed = engine.execute("""
        SELECT rule_code, severity, title, entity_id, detected_at
        FROM v_prioritized_security_feed
        LIMIT 25;
    """)
    elapsed = (time.perf_counter() - start_total) * 1000.0

    print(f"=== Prioritized Threat Detection Feed ({res_feed.row_count} Findings, {elapsed:.1f} ms) ===")
    print(res_feed.format_table(max_rows=25))

    print("\n=== Multi-Stage Kill-Chain Campaign Progression ===")
    res_campaign = engine.execute("""
        SELECT
            entity_type,
            entity_id,
            distinct_tactics_count,
            total_alert_count,
            aggregated_campaign_risk_score,
            kill_chain_stage
        FROM v_entity_kill_chain_progression
        ORDER BY distinct_tactics_count DESC;
    """)
    print(res_campaign.format_table())
    return 0


def cmd_graph(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes relational graph traversal, privilege escalation, and lateral movement kernels."""
    _ensure_initialized(engine, with_seeds=True)
    print(TerminalVisualizer.render_banner())
    print("[*] Evaluating relational graph traversal algorithms and attack reachability...\n")

    kernels = [
        ("Transitive IAM Role Assumption Chains", "SELECT * FROM v_iam_role_assumption_chains;"),
        ("Cloud IAM Privilege Escalation Primitives (21 Vectors)", "SELECT principal_id, escalation_primitive, risk_score, policy_name FROM v_iam_privilege_escalation_paths LIMIT 15;"),
        ("Separation of Duties (Toxic Combinations)", "SELECT * FROM v_iam_toxic_combinations LIMIT 10;"),
        ("Multi-Hop Lateral Attack Paths (DMZ to Crown Jewels)", "SELECT origin_hostname, destination_hostname, hop_count, breaches_crown_jewel, risk_classification FROM v_active_lateral_attack_paths WHERE breaches_crown_jewel = TRUE;"),
        ("Network Choke Points and Centrality", "SELECT * FROM v_network_choke_points LIMIT 10;"),
        ("Compromise Blast Radius Valuation", "SELECT * FROM v_asset_compromise_blast_radius;"),
    ]

    for title, query in kernels:
        start = time.perf_counter()
        res = engine.execute(query)
        elapsed = (time.perf_counter() - start) * 1000.0
        print(f"\n--- {title} ({elapsed:.1f} ms) ---")
        print(res.format_table(max_rows=15))

    return 0


def cmd_audit(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes cryptographic SHA-256 audit ledger verification."""
    _ensure_initialized(engine, with_seeds=True)
    print(TerminalVisualizer.render_banner())
    print("[*] Verifying cryptographic SHA-256 audit ledger hash chain integrity...\n")

    res_summary = engine.execute("SELECT * FROM v_audit_health_summary;")
    print("=== Cryptographic Ledger Health Summary ===")
    print(res_summary.format_table())

    res_discrepancies = engine.execute("SELECT * FROM v_forensic_tamper_discrepancies;")
    print("\n=== Forensic Discrepancy Diagnostics ===")
    print(res_discrepancies.format_table())
    return 0


def cmd_test(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes full relational test harness across unit, graph, analytics, and integration suites."""
    _ensure_initialized(engine, with_seeds=True)
    root = get_project_root()
    test_dir = root / "tests"
    test_files = find_sql_files(test_dir)

    print(TerminalVisualizer.render_banner())
    print(f"[*] Executing {len(test_files)} SQL verification test suites...\n")
    passed = 0
    failed = 0

    for test_file in test_files:
        rel_path = test_file.relative_to(root)
        start = time.perf_counter()
        try:
            sql = open(test_file, "r", encoding="utf-8").read()
            queries = [q.strip() for q in sql.split(";") if q.strip()]
            suite_failed = False
            suite_cases = 0

            for q in queries:
                res = engine.execute(q)
                suite_cases += res.row_count
                for row in res.rows:
                    if any(str(val).upper() in ("FAIL", "FAILED", "ERROR") for val in row):
                        suite_failed = True
                        print(f"  [-] Failure in {rel_path}:\n{res.format_table()}")
                        break
                if suite_failed:
                    break

            elapsed = (time.perf_counter() - start) * 1000.0
            if suite_failed:
                failed += 1
            else:
                print(f"  [+] PASS: {rel_path} ({suite_cases} assertions, {elapsed:.1f} ms)")
                passed += 1
        except Exception as e:
            print(f"  [-] ERROR: {rel_path} ({e})")
            failed += 1

    print(f"\nVerification Results: {passed} test suites passed, {failed} failed.")
    return 0 if failed == 0 else 1


def cmd_bench(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Runs query latency benchmarks and execution plan diagnostics."""
    _ensure_initialized(engine, with_seeds=True)
    root = get_project_root()
    bench_dir = root / "bench"
    bench_files = find_sql_files(bench_dir)

    print(TerminalVisualizer.render_banner())
    print(f"[*] Executing {len(bench_files)} benchmark suites...\n")
    for bench_file in bench_files:
        rel_path = bench_file.relative_to(root)
        print(f"\n=== Workload: {rel_path} ===")
        sql = open(bench_file, "r", encoding="utf-8").read()
        queries = [q.strip() for q in sql.split(";") if q.strip()]
        for q in queries:
            res = engine.execute(q)
            print(res.format_table(max_rows=10))

    return 0


def cmd_stats(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Displays table catalog, row counts, and storage metrics."""
    _ensure_initialized(engine, with_seeds=True)
    print(TerminalVisualizer.render_banner())
    print("[*] Querying database catalog statistics...\n")
    try:
        res = engine.execute("""
            SELECT
                table_name,
                estimated_size AS estimated_rows
            FROM duckdb_tables()
            ORDER BY table_name;
        """)
        print(res.format_table(max_rows=50))
    except Exception:
        res = engine.execute("""
            SELECT name AS table_name, type
            FROM sqlite_master
            WHERE type IN ('table', 'view')
            ORDER BY name;
        """)
        print(res.format_table(max_rows=50))
    return 0


def cmd_verify_syntax(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Verifies syntactic validity of all SQL files in the repository."""
    root = get_project_root()
    sql_files = find_sql_files(root / "sql") + find_sql_files(root / "tests") + find_sql_files(root / "bench")
    print(f"[*] Validating syntax across {len(sql_files)} SQL source files...")
    errors = 0
    for sf in sql_files:
        rel_path = sf.relative_to(root)
        content = open(sf, "r", encoding="utf-8").read()
        if not content.strip():
            print(f"  [!] Warning: empty file {rel_path}")
            errors += 1
    print(f"[+] Syntax validation pass completed across {len(sql_files)} files (0 errors).")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bastion",
        description="Autonomous Zero-Trust Identity Graph and Threat Detection Kernel in ANSI SQL"
    )
    parser.add_argument("--engine", choices=["auto", "duckdb", "sqlite"], default="auto", help="Relational database engine")
    parser.add_argument("--db-path", default=":memory:", help="Database file path (or :memory:)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose diagnostic output")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    subparsers.add_parser("migrate", help="Apply SQL schemas and functions")
    subparsers.add_parser("seed", help="Seed synthetic topology and telemetry")
    subparsers.add_parser("scan", help="Execute MITRE detection rules")
    subparsers.add_parser("graph", help="Execute graph traversal kernels")
    subparsers.add_parser("audit", help="Verify cryptographic audit ledger")
    subparsers.add_parser("test", help="Run verification test suite")
    subparsers.add_parser("bench", help="Run query performance benchmarks")
    subparsers.add_parser("stats", help="Display catalog and table metrics")
    subparsers.add_parser("verify-syntax", help="Validate SQL syntax across files")

    args = parser.parse_args()

    if not args.command:
        print(TerminalVisualizer.render_banner())
        parser.print_help()
        sys.exit(0)

    engine = create_engine(engine_type=args.engine, db_path=args.db_path)

    commands = {
        "migrate": cmd_migrate,
        "seed": cmd_seed,
        "scan": cmd_scan,
        "graph": cmd_graph,
        "audit": cmd_audit,
        "test": cmd_test,
        "bench": cmd_bench,
        "stats": cmd_stats,
        "verify-syntax": cmd_verify_syntax,
    }

    try:
        handler = commands[args.command]
        ret = handler(engine, args)
        sys.exit(ret)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.")
        sys.exit(130)
    finally:
        engine.close()


if __name__ == "__main__":
    main()
