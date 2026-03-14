-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/schema/04_intel.sql
-- Description: Threat intelligence taxonomy, Indicators of Compromise (IOCs),
--              threat actors, campaign signatures, and MITRE ATT&CK Enterprise Matrix.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. MITRE ATT&CK Enterprise Matrix Taxonomy
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_mitre_tactics (
    tactic_id           VARCHAR(64) PRIMARY KEY,
    tactic_code         VARCHAR(16) NOT NULL UNIQUE, -- e.g. TA0001, TA0002
    name                VARCHAR(128) NOT NULL,
    description         TEXT NOT NULL,
    display_order       INTEGER NOT NULL UNIQUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intel_mitre_techniques (
    technique_id        VARCHAR(64) PRIMARY KEY,
    tactic_id           VARCHAR(64) NOT NULL REFERENCES intel_mitre_tactics(tactic_id),
    technique_code      VARCHAR(16) NOT NULL UNIQUE, -- e.g. T1078, T1078.004
    name                VARCHAR(255) NOT NULL,
    is_subtechnique     BOOLEAN NOT NULL DEFAULT FALSE,
    parent_technique_id VARCHAR(64) REFERENCES intel_mitre_techniques(technique_id),
    description         TEXT NOT NULL,
    detection_guidance  TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. Threat Actors and Adversary Campaign Profiling
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_threat_actors (
    actor_id            VARCHAR(64) PRIMARY KEY,
    actor_code          VARCHAR(64) NOT NULL UNIQUE, -- e.g. APT29, FIN7, WIZARD_SPIDER
    name                VARCHAR(128) NOT NULL,
    aliases             VARCHAR(512),               -- Comma-separated alias list
    country_origin      VARCHAR(64),
    primary_motivation  VARCHAR(32) NOT NULL CHECK (primary_motivation IN (
                            'ESPIONAGE', 'FINANCIAL', 'SABOTAGE', 'HACKTIVISM', 'RANSOMWARE'
                        )),
    target_sectors      VARCHAR(512),
    first_observed_year INTEGER,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intel_actor_techniques (
    mapping_id          VARCHAR(64) PRIMARY KEY,
    actor_id            VARCHAR(64) NOT NULL REFERENCES intel_threat_actors(actor_id),
    technique_id        VARCHAR(64) NOT NULL REFERENCES intel_mitre_techniques(technique_id),
    observed_frequency  VARCHAR(16) NOT NULL DEFAULT 'FREQUENT' CHECK (observed_frequency IN ('OCCASIONAL', 'FREQUENT', 'SIGNATURE')),
    confidence_score    NUMERIC(5,2) NOT NULL DEFAULT 85.00 CHECK (confidence_score BETWEEN 0.0 AND 100.0),
    CONSTRAINT uq_actor_technique UNIQUE (actor_id, technique_id)
);

-- ----------------------------------------------------------------------------
-- 3. Indicators of Compromise (IOCs)
-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS intel_indicators_ip (
    indicator_id        VARCHAR(64) PRIMARY KEY,
    ip_address          VARCHAR(64) NOT NULL,
    cidr_prefix         INTEGER NOT NULL DEFAULT 32,
    threat_category     VARCHAR(32) NOT NULL CHECK (threat_category IN (
                            'COMMAND_AND_CONTROL', 'TOR_EXIT_NODE', 'SCANNER',
                            'MALWARE_DROPPER', 'BRUTE_FORCE_SOURCE', 'ANONYMIZING_PROXY'
                        )),
    associated_actor_id VARCHAR(64) REFERENCES intel_threat_actors(actor_id),
    confidence_score    NUMERIC(5,2) NOT NULL DEFAULT 80.00 CHECK (confidence_score BETWEEN 0.0 AND 100.0),
    source_feed         VARCHAR(128) NOT NULL,
    first_seen          TIMESTAMP NOT NULL,
    last_seen           TIMESTAMP NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT chk_ip_seen CHECK (last_seen >= first_seen)
);

CREATE TABLE IF NOT EXISTS intel_indicators_domain (
    indicator_id        VARCHAR(64) PRIMARY KEY,
    domain_name         VARCHAR(255) NOT NULL,
    threat_category     VARCHAR(32) NOT NULL CHECK (threat_category IN (
                            'PHISHING', 'C2_DOMAIN', 'DGA_SUSPECT', 'MALWARE_HOST', 'EXFILTRATION_ENDPOINT'
                        )),
    associated_actor_id VARCHAR(64) REFERENCES intel_threat_actors(actor_id),
    confidence_score    NUMERIC(5,2) NOT NULL DEFAULT 80.00 CHECK (confidence_score BETWEEN 0.0 AND 100.0),
    source_feed         VARCHAR(128) NOT NULL,
    first_seen          TIMESTAMP NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS intel_indicators_hash (
    indicator_id        VARCHAR(64) PRIMARY KEY,
    hash_sha256         VARCHAR(64) NOT NULL UNIQUE,
    hash_md5            VARCHAR(32),
    malware_family      VARCHAR(128) NOT NULL,
    file_type           VARCHAR(64) NOT NULL,
    threat_category     VARCHAR(32) NOT NULL CHECK (threat_category IN (
                            'RANSOMWARE', 'BACKDOOR', 'INFOSTEALER', 'DROPPER', 'WEBSHELL', 'ROOTKIT'
                        )),
    associated_actor_id VARCHAR(64) REFERENCES intel_threat_actors(actor_id),
    confidence_score    NUMERIC(5,2) NOT NULL DEFAULT 95.00 CHECK (confidence_score BETWEEN 0.0 AND 100.0),
    source_feed         VARCHAR(128) NOT NULL,
    first_seen          TIMESTAMP NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

-- Fast index lookups for stream-filtering against telemetry
CREATE INDEX IF NOT EXISTS idx_intel_ip_val ON intel_indicators_ip(ip_address, is_active);
CREATE INDEX IF NOT EXISTS idx_intel_domain_name ON intel_indicators_domain(domain_name, is_active);
CREATE INDEX IF NOT EXISTS idx_intel_hash_val ON intel_indicators_hash(hash_sha256, is_active);
CREATE INDEX IF NOT EXISTS idx_techniques_tactic ON intel_mitre_techniques(tactic_id);
CREATE INDEX IF NOT EXISTS idx_techniques_code ON intel_mitre_techniques(technique_code);
