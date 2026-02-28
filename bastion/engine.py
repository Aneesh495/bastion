"""Multi-engine relational database abstraction layer.

Supports DuckDB (CLI and Python module) and SQLite with custom mathematical
and cryptographic function extensions for executing Bastion SQL kernels.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class QueryResult:
    """Encapsulates the tabular output and execution metrics of a SQL query."""
    columns: List[str]
    rows: List[List[Any]]
    execution_time_ms: float
    row_count: int

    def to_dicts(self) -> List[Dict[str, Any]]:
        """Converts rows to a list of column-to-value dictionaries."""
        return [dict(zip(self.columns, row)) for row in self.rows]

    def format_table(self, max_rows: int = 50, max_col_width: int = 32) -> str:
        """Formats tabular results into an ASCII table."""
        if not self.columns:
            return "(Empty result set)"

        display_rows = self.rows[:max_rows]
        str_rows = [
            [
                (str(v)[: max_col_width - 3] + "..." if len(str(v)) > max_col_width else str(v))
                if v is not None else "NULL"
                for v in row
            ]
            for row in display_rows
        ]

        widths = [len(col) for col in self.columns]
        for row in str_rows:
            for i, val in enumerate(row):
                widths[i] = max(widths[i], len(val))

        sep_line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
        header_line = "| " + " | ".join(col.ljust(w) for col, w in zip(self.columns, widths)) + " |"

        lines = [sep_line, header_line, sep_line]
        for row in str_rows:
            lines.append("| " + " | ".join(val.ljust(w) for val, w in zip(row, widths)) + " |")
        lines.append(sep_line)

        if len(self.rows) > max_rows:
            lines.append(f"... ({len(self.rows) - max_rows} additional rows truncated)")
        lines.append(f"({self.row_count} rows, {self.execution_time_ms:.2f} ms)")
        return "\n".join(lines)


class DatabaseEngine:
    """Base relational engine interface."""

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> QueryResult:
        raise NotImplementedError

    def execute_script(self, sql_script: str) -> None:
        raise NotImplementedError

    def execute_file(self, file_path: Union[str, Path]) -> None:
        path = Path(file_path)
        with open(path, "r", encoding="utf-8") as f:
            script = f.read()
        self.execute_script(script)

    def close(self) -> None:
        pass


class SQLiteEngine(DatabaseEngine):
    """In-memory or persistent SQLite engine with analytical extensions."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._register_extensions()

    def _register_extensions(self) -> None:
        """Registers math, cryptographic, and string functions for ANSI compatibility."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA foreign_keys = ON;")
        cur.execute("PRAGMA journal_mode = WAL;")

        # Cryptographic hashes
        self.conn.create_function("sha256", 1, lambda s: hashlib.sha256(str(s).encode("utf-8")).hexdigest() if s is not None else None)
        self.conn.create_function("md5", 1, lambda s: hashlib.md5(str(s).encode("utf-8")).hexdigest() if s is not None else None)

        # Extended mathematical operations
        self.conn.create_function("sqrt", 1, lambda x: math.sqrt(float(x)) if x is not None and float(x) >= 0 else None)
        self.conn.create_function("power", 2, lambda x, y: math.pow(float(x), float(y)) if x is not None and y is not None else None)
        self.conn.create_function("log10", 1, lambda x: math.log10(float(x)) if x is not None and float(x) > 0 else None)
        self.conn.create_function("ln", 1, lambda x: math.log(float(x)) if x is not None and float(x) > 0 else None)
        self.conn.create_function("exp", 1, lambda x: math.exp(float(x)) if x is not None else None)

        # Regular expressions
        self.conn.create_function("regexp", 2, lambda pattern, text: 1 if (text is not None and re.search(pattern, str(text))) else 0)

        # Levenshtein distance fallback
        def _levenshtein(s1: Optional[str], s2: Optional[str]) -> Optional[int]:
            if s1 is None or s2 is None:
                return None
            if len(s1) < len(s2):
                return _levenshtein(s2, s1)
            if len(s2) == 0:
                return len(s1)
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]

        self.conn.create_function("levenshtein", 2, _levenshtein)

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> QueryResult:
        start_time = time.perf_counter()
        cursor = self.conn.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)

        if cursor.description:
            columns = [col[0] for col in cursor.description]
            raw_rows = cursor.fetchall()
            rows = [list(r) for r in raw_rows]
        else:
            columns = []
            rows = []
            self.conn.commit()

        elapsed = (time.perf_counter() - start_time) * 1000.0
        return QueryResult(
            columns=columns,
            rows=rows,
            execution_time_ms=elapsed,
            row_count=len(rows)
        )

    def execute_script(self, sql_script: str) -> None:
        self.conn.executescript(sql_script)

    def close(self) -> None:
        self.conn.close()


class DuckDBCLIEngine(DatabaseEngine):
    """High-performance DuckDB execution engine utilizing DuckDB binary."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.binary = shutil.which("duckdb") or "/opt/homebrew/bin/duckdb"
        if not os.path.exists(self.binary):
            raise RuntimeError(f"DuckDB binary not found at {self.binary}")

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> QueryResult:
        start_time = time.perf_counter()
        # Ensure json output for reliable typed parsing
        cmd = [self.binary, "-dark-mode", "-json", self.db_path]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=sql)
        if proc.returncode != 0:
            raise RuntimeError(f"DuckDB query execution failed (code {proc.returncode}): {stderr}")

        stdout = stdout.strip()
        if not stdout:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return QueryResult(columns=[], rows=[], execution_time_ms=elapsed, row_count=0)

        try:
            records = json.loads(stdout)
            if not isinstance(records, list):
                records = [records]
            if not records:
                columns = []
                rows = []
            else:
                columns = list(records[0].keys())
                rows = [[rec.get(c) for c in columns] for rec in records]
        except Exception:
            # Fallback if raw output
            columns = ["raw_output"]
            rows = [[stdout]]

        elapsed = (time.perf_counter() - start_time) * 1000.0
        return QueryResult(
            columns=columns,
            rows=rows,
            execution_time_ms=elapsed,
            row_count=len(rows)
        )

    def execute_script(self, sql_script: str) -> None:
        cmd = [self.binary, "-dark-mode", self.db_path]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=sql_script)
        if proc.returncode != 0:
            raise RuntimeError(f"DuckDB script execution error: {stderr}")


def create_engine(engine_type: str = "auto", db_path: str = ":memory:") -> DatabaseEngine:
    """Factory creating appropriate relational database engine instance."""
    if engine_type == "duckdb":
        return DuckDBCLIEngine(db_path)
    elif engine_type == "sqlite":
        return SQLiteEngine(db_path)
    elif engine_type == "auto":
        # Check if duckdb binary is readily available
        duckdb_path = shutil.which("duckdb") or "/opt/homebrew/bin/duckdb"
        if os.path.exists(duckdb_path):
            try:
                engine = DuckDBCLIEngine(db_path)
                # Quick verification probe
                engine.execute("SELECT 1 AS probe;")
                return engine
            except Exception:
                pass
        return SQLiteEngine(db_path)
    else:
        raise ValueError(f"Unsupported engine type: {engine_type}")
