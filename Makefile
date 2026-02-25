# Bastion: Autonomous Zero-Trust Identity Graph and Threat Detection Kernel in ANSI SQL
# Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.

.PHONY: all init schema seed test bench clean lint check-no-em-dash help

PYTHON ?= python3
SQL_DIR ?= sql
TEST_DIR ?= tests

all: lint schema test

help:
	@echo "Bastion Build Targets:"
	@echo "  make init      : Initialize runtime directories and dependencies"
	@echo "  make schema    : Compile and validate SQL schemas and DDL"
	@echo "  make seed      : Ingest synthetic enterprise topology and attack telemetry"
	@echo "  make test      : Execute unit, graph, analytics, rule, and integration tests"
	@echo "  make bench     : Run relational query performance and plan benchmarks"
	@echo "  make lint      : Run static checks and verify formatting"
	@echo "  make clean     : Clean temporary databases, logs, and cache artifacts"

init:
	@mkdir -p .bastion_data build dist

schema: init
	@$(PYTHON) -m bastion.cli migrate

seed: schema
	@$(PYTHON) -m bastion.cli seed

test: schema seed
	@$(PYTHON) -m bastion.cli test

bench: schema seed
	@$(PYTHON) -m bastion.cli bench

lint: check-no-em-dash
	@$(PYTHON) -m bastion.cli verify-syntax

check-no-em-dash:
	@echo "Verifying zero em dashes across all code and documentation files..."
	@! grep -rn "—" sql/ docs/ bastion/ tests/ *.md 2>/dev/null || (echo "ERROR: Em dash found! Must not use em dashes." && exit 1)
	@echo "Em dash check passed: zero em dashes found."

clean:
	@rm -rf .bastion_data build dist *.egg-info __pycache__ */__pycache__ */*/__pycache__ *.db *.sqlite *.duckdb
