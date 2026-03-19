-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/06_detection.sql
-- Description: Detection rule registry, execution triggers, structured alert schemas,
--              suppression filters, and multi-tier severity scoring models.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Detection Rule Catalog
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id             VARCHAR(64) PRIMARY KEY,
    rule_code           VARCHAR(32) NOT NULL UNIQUE, -- e.g. BST-T1078-01
    name                VARCHAR(255) NOT NULL,
    tactic_id           VARCHAR(64) NOT NULL REFERENCES intel_mitre_tactics(tactic_id),
    technique_id        VARCHAR(64) NOT NULL REFERENCES intel_mitre_techniques(technique_id),
    severity            VARCHAR(16) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    base_risk_score     NUMERIC(5,2) NOT NULL CHECK (base_risk_score BETWEEN 0.0 AND 100.0),
    fidelity_score      NUMERIC(5,2) NOT NULL DEFAULT 80.00 CHECK (fidelity_score BETWEEN 0.0 AND 100.0),
    evaluation_window_mins INTEGER NOT NULL DEFAULT 60,
    suppression_period_mins INTEGER NOT NULL DEFAULT 120,
    sql_definition      TEXT,
    is_stateful         BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. Structured Alerts and Detection Findings
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS detection_alerts (
    alert_id            VARCHAR(64) PRIMARY KEY,
    rule_id             VARCHAR(64) NOT NULL REFERENCES detection_rules(rule_id),
    account_id          VARCHAR(64) REFERENCES core_cloud_accounts(account_id),
    entity_type         VARCHAR(32) NOT NULL CHECK (entity_type IN ('PRINCIPAL', 'ASSET', 'SUBNET', 'BUCKET', 'CREDENTIAL', 'NETWORK_FLOW')),
    entity_id           VARCHAR(64) NOT NULL,
    detected_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    window_start        TIMESTAMP NOT NULL,
    window_end          TIMESTAMP NOT NULL,
    severity            VARCHAR(16) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    confidence_score    NUMERIC(5,2) NOT NULL CHECK (confidence_score BETWEEN 0.0 AND 100.0),
    composite_risk_score NUMERIC(5,2) NOT NULL CHECK (composite_risk_score BETWEEN 0.0 AND 100.0),
    title               VARCHAR(255) NOT NULL,
    summary             TEXT NOT NULL,
    evidence_json       TEXT NOT NULL,              -- Structured JSON containing triggering log events
    tactic_code         VARCHAR(16) NOT NULL,       -- e.g. TA0001
    technique_code      VARCHAR(16) NOT NULL,       -- e.g. T1078
    status              VARCHAR(32) NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW', 'CORRELATED', 'SUPPRESSED', 'RESOLVED', 'FALSE_POSITIVE')),
    correlation_id      VARCHAR(64),
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_alert_window CHECK (window_end >= window_start)
);

-- ----------------------------------------------------------------------------
-- 3. Dynamic Alert Suppression Filters
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS detection_suppressions (
    suppression_id      VARCHAR(64) PRIMARY KEY,
    rule_id             VARCHAR(64) REFERENCES detection_rules(rule_id),
    entity_type         VARCHAR(32),
    entity_id           VARCHAR(64),
    ip_or_cidr          VARCHAR(64),
    suppression_reason  TEXT NOT NULL,
    created_by          VARCHAR(64) NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at          TIMESTAMP NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT chk_suppression_expiry CHECK (expires_at > created_at)
);

-- ----------------------------------------------------------------------------
-- 4. Analytical Views for Triaged Queues
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_active_high_severity_alerts AS
SELECT
    a.alert_id,
    a.rule_id,
    r.rule_code,
    a.severity,
    a.composite_risk_score,
    a.entity_type,
    a.entity_id,
    a.tactic_code,
    a.technique_code,
    a.title,
    a.detected_at
FROM detection_alerts a
JOIN detection_rules r ON a.rule_id = r.rule_id
WHERE a.status IN ('NEW', 'CORRELATED')
  AND a.severity IN ('CRITICAL', 'HIGH')
ORDER BY a.composite_risk_score DESC, a.detected_at DESC;

CREATE INDEX IF NOT EXISTS idx_alerts_entity ON detection_alerts(entity_type, entity_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_status ON detection_alerts(rule_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_tactic ON detection_alerts(tactic_code);
CREATE INDEX IF NOT EXISTS idx_rules_tactic ON detection_rules(tactic_id);
