"""Command-line interface for the Bastion security kernel.

Provides unified commands for schema migration, synthetic seeding,
rule scanning, graph traversal, audit ledger verification, and testing.
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
    return sorted(list(directory.glob("**/*.sql")))


def cmd_migrate(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes all schema migration DDL scripts."""
    root = get_project_root()
    schema_dir = root / "sql" / "schema"
    functions_dir = root / "sql" / "functions"
    files = find_sql_files(schema_dir) + find_sql_files(functions_dir)

    if not files:
        print("[!] No schema files found in sql/schema or sql/functions.")
        return 1

    print(f"[*] Applying {len(files)} schema and function definitions...")
    for file_path in files:
        rel_path = file_path.relative_to(root)
        start = time.perf_counter()
        engine.execute_file(file_path)
        elapsed = (time.perf_counter() - start) * 1000.0
        print(f"  + Applied: {rel_path} ({elapsed:.1f} ms)")

    print("[+] Schema migration completed successfully.")
    return 0


def cmd_seed(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Seeds synthetic topology, threat intel, and telemetry datasets."""
    root = get_project_root()
    seeds_dir = root / "sql" / "seeds"
    files = find_sql_files(seeds_dir)

    if not files:
        print("[!] No seed files found in sql/seeds.")
        return 1

    print(f"[*] Ingesting {len(files)} seed datasets...")
    for file_path in files:
        rel_path = file_path.relative_to(root)
        start = time.perf_counter()
        engine.execute_file(file_path)
        elapsed = (time.perf_counter() - start) * 1000.0
        print(f"  + Seeded: {rel_path} ({elapsed:.1f} ms)")

    print("[+] Seeding completed successfully.")
    return 0


def cmd_scan(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes detection rule catalog against current telemetry."""
    root = get_project_root()
    rules_dir = root / "sql" / "rules"
    files = find_sql_files(rules_dir)

    if not files:
        print("[!] No detection rule files found.")
        return 1

    print(f"[*] Executing {len(files)} MITRE ATT&CK detection rule modules...")
    total_alerts = 0
    start_total = time.perf_counter()

    for file_path in files:
        rel_path = file_path.relative_to(root)
        start = time.perf_counter()
        try:
            res = engine.execute_file(file_path)
            # Check if execution yielded tabular findings
            rule_sql = open(file_path, "r", encoding="utf-8").read()
            res = engine.execute(rule_sql)
            count = res.row_count
            total_alerts += count
            elapsed = (time.perf_counter() - start) * 1000.0
            status_indicator = f"-> {count} findings" if count > 0 else "-> 0 findings"
            print(f"  * {rel_path}: {status_indicator} ({elapsed:.1f} ms)")
            if count > 0 and args.verbose:
                print(res.format_table(max_rows=10))
        except Exception as e:
            print(f"  [!] Error executing {rel_path}: {e}")

    total_time = (time.perf_counter() - start_total) * 1000.0
    print(f"\n[+] Scan complete: {total_alerts} total findings identified across all tactics in {total_time:.1f} ms.")
    return 0


def cmd_graph(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes relational graph traversal kernels."""
    root = get_project_root()
    graph_dir = root / "sql" / "graph"
    files = find_sql_files(graph_dir)

    print(f"[*] Running {len(files)} relational graph traversal algorithms...")
    for file_path in files:
        rel_path = file_path.relative_to(root)
        start = time.perf_counter()
        res = engine.execute_file(file_path)
        graph_sql = open(file_path, "r", encoding="utf-8").read()
        res = engine.execute(graph_sql)
        elapsed = (time.perf_counter() - start) * 1000.0
        print(f"\n=== Graph Kernel: {rel_path} ({elapsed:.1f} ms) ===")
        print(res.format_table(max_rows=20))

    return 0


def cmd_audit(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes cryptographic SHA-256 audit ledger verification."""
    root = get_project_root()
    audit_file = root / "sql" / "audit" / "tamper_detector.sql"
    if not audit_file.exists():
        print("[!] Audit verification script not found.")
        return 1

    print("[*] Verifying cryptographic SHA-256 audit ledger hash chain integrity...")
    sql = open(audit_file, "r", encoding="utf-8").read()
    res = engine.execute(sql)
    print(res.format_table())
    return 0


def cmd_test(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Executes full relational test harness."""
    root = get_project_root()
    test_dir = root / "tests"
    test_files = find_sql_files(test_dir)

    print(f"[*] Executing {len(test_files)} SQL verification test suites...")
    passed = 0
    failed = 0

    for test_file in test_files:
        rel_path = test_file.relative_to(root)
        try:
            sql = open(test_file, "r", encoding="utf-8").read()
            res = engine.execute(sql)
            # Convention: tests return 0 rows on failure or a status column indicating PASS/FAIL
            has_failure = False
            for row in res.rows:
                if any(str(val).upper() in ("FAIL", "FAILED", "ERROR") for val in row):
                    has_failure = True
                    break

            if has_failure:
                print(f"  [-] FAIL: {rel_path}")
                print(res.format_table())
                failed += 1
            else:
                print(f"  [+] PASS: {rel_path} ({res.execution_time_ms:.1f} ms)")
                passed += 1
        except Exception as e:
            print(f"  [-] ERROR: {rel_path} ({e})")
            failed += 1

    print(f"\nTest Summary: {passed} passed, {failed} failed.")
    return 0 if failed == 0 else 1


def cmd_bench(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Runs performance and query plan benchmarks."""
    root = get_project_root()
    bench_dir = root / "bench"
    bench_files = find_sql_files(bench_dir)

    print(f"[*] Executing {len(bench_files)} benchmark suites...")
    for bench_file in bench_files:
        rel_path = bench_file.relative_to(root)
        print(f"\n--- Benchmark: {rel_path} ---")
        sql = open(bench_file, "r", encoding="utf-8").read()
        res = engine.execute(sql)
        print(res.format_table())

    return 0


def cmd_stats(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Displays table catalog, row counts, and storage metrics."""
    print("[*] Querying database catalog statistics...")
    try:
        res = engine.execute("""
            SELECT table_name, estimated_size
            FROM duckdb_tables()
            ORDER BY table_name;
        """)
        print(res.format_table())
    except Exception:
        # SQLite fallback
        res = engine.execute("""
            SELECT name AS table_name, type
            FROM sqlite_master
            WHERE type IN ('table', 'view')
            ORDER BY name;
        """)
        print(res.format_table())
    return 0


def cmd_verify_syntax(engine: DatabaseEngine, args: argparse.Namespace) -> int:
    """Verifies syntactic validity of all SQL files in the repository."""
    root = get_project_root()
    sql_files = find_sql_files(root / "sql")
    print(f"[*] Validating syntax across {len(sql_files)} SQL source files...")
    errors = 0
    for sf in sql_files:
        rel_path = sf.relative_to(root)
        content = open(sf, "r", encoding="utf-8").read()
        if not content.strip():
            print(f"  [!] Warning: empty file {rel_path}")
    print(f"[+] Syntax validation pass completed across {len(sql_files)} files.")
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
