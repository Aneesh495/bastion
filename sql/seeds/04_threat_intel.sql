-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/seeds/04_threat_intel.sql
-- Description: Threat intelligence indicators: APT actors, C2 infrastructure,
--              Tor exit nodes, malicious domains, and malware file signatures.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Threat Actors and Adversary Groups
-- ----------------------------------------------------------------------------

INSERT INTO intel_threat_actors (
    actor_id, actor_code, name, aliases, country_origin, primary_motivation, target_sectors, first_observed_year, is_active
) VALUES
('act-apt29',   'APT29',         'Cozy Bear',       'Midnight Blizzard, Nobelium, The Dukes', 'RU', 'ESPIONAGE',  'Government, Defense, Technology, Think Tanks', 2008, TRUE),
('act-fin7',    'FIN7',          'Carbanak Group',  'Carbon Spider, Sangria Tempest',        'RU', 'FINANCIAL',  'Retail, Hospitality, Banking, Financial Services', 2013, TRUE),
('act-lazarus', 'LAZARUS_GROUP', 'Lazarus Group',   'HIDDEN COBRA, Guardians of Peace',      'KP', 'SABOTAGE',   'Cryptocurrency, Aerospace, Defense, Energy', 2009, TRUE),
('act-wizard',  'WIZARD_SPIDER', 'Wizard Spider',   'UNC1878, Grim Spider (Ryuk/Conti)',     'RU', 'RANSOMWARE', 'Healthcare, Manufacturing, Critical Infrastructure', 2018, TRUE)
ON CONFLICT (actor_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. Actor TTP Mappings to MITRE ATT&CK Techniques
-- ----------------------------------------------------------------------------

INSERT INTO intel_actor_techniques (mapping_id, actor_id, technique_id, observed_frequency, confidence_score) VALUES
('map-01', 'act-apt29',   'tech-1078-004', 'SIGNATURE', 98.0),
('map-02', 'act-apt29',   'tech-1059-001', 'FREQUENT',  95.0),
('map-03', 'act-apt29',   'tech-1048-003', 'SIGNATURE', 94.0),
('map-04', 'act-fin7',    'tech-1190',     'FREQUENT',  90.0),
('map-05', 'act-fin7',    'tech-1003-001', 'SIGNATURE', 95.0),
('map-06', 'act-wizard',  'tech-1486',     'SIGNATURE', 99.0),
('map-07', 'act-wizard',  'tech-1562-001', 'FREQUENT',  92.0)
ON CONFLICT (mapping_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. Indicator IP Addresses (C2 Servers, Tor Exit Nodes, Brute-Force Sources)
-- ----------------------------------------------------------------------------

INSERT INTO intel_indicators_ip (
    indicator_id, ip_address, cidr_prefix, threat_category, associated_actor_id,
    confidence_score, source_feed, first_seen, last_seen, is_active
) VALUES
('ind-ip-01', '198.51.100.42',  32, 'COMMAND_AND_CONTROL', 'act-apt29',   99.0, 'Mandiant-Threat-Intel', '2026-09-01 00:00:00', '2026-10-17 00:00:00', TRUE),
('ind-ip-02', '198.51.100.99',  32, 'TOR_EXIT_NODE',       NULL,          95.0, 'TorProject-Exit-List',  '2026-08-15 00:00:00', '2026-10-17 00:00:00', TRUE),
('ind-ip-03', '203.0.113.200',  32, 'COMMAND_AND_CONTROL', 'act-fin7',    92.0, 'CrowdStrike-Falcon',    '2026-09-10 00:00:00', '2026-10-17 00:00:00', TRUE),
('ind-ip-04', '192.0.2.66',     32, 'BRUTE_FORCE_SOURCE',  NULL,          88.0, 'AbuseIPDB-High-Score',  '2026-10-01 00:00:00', '2026-10-17 00:00:00', TRUE),
('ind-ip-05', '198.51.100.150', 32, 'ANONYMIZING_PROXY',  NULL,          85.0, 'Spamhaus-DROP',         '2026-07-20 00:00:00', '2026-10-17 00:00:00', TRUE)
ON CONFLICT (indicator_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 4. Malicious Domains
-- ----------------------------------------------------------------------------

INSERT INTO intel_indicators_domain (
    indicator_id, domain_name, threat_category, associated_actor_id, confidence_score, source_feed, first_seen, is_active
) VALUES
('ind-dom-01', 'bastion-sec-portal-login.com', 'PHISHING',   'act-apt29', 95.0, 'Brand-Protection-Feed', '2026-10-10 00:00:00', TRUE),
('ind-dom-02', 'api-cloud-sync-c2.net',        'C2_DOMAIN',  'act-apt29', 98.0, 'Recorded-Future',       '2026-09-15 00:00:00', TRUE),
('ind-dom-03', 'update-packages-cdn.biz',       'MALWARE_HOST','act-fin7',  90.0, 'Unit42-Threat-Feed',   '2026-10-05 00:00:00', TRUE)
ON CONFLICT (indicator_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 5. Malware Cryptographic File Signatures (SHA-256)
-- ----------------------------------------------------------------------------

INSERT INTO intel_indicators_hash (
    indicator_id, hash_sha256, hash_md5, malware_family, file_type, threat_category, associated_actor_id, confidence_score, source_feed, first_seen, is_active
) VALUES
('ind-hsh-01', '5d41402abc4b2a76b9719d911017c592b0a1d47372cf017d91e6dc8ec7b0934d', 'd41d8cd98f00b204e9800998ecf8427e', 'Mimikatz', 'PE32_EXE', 'INFOSTEALER', 'act-fin7',   99.0, 'VirusTotal-Trusted', '2026-01-01 00:00:00', TRUE),
('ind-hsh-02', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'e3b0c44298fc1c149afbf4c8996fb924', 'CobaltStrike', 'DLL',   'BACKDOOR',    'act-apt29',  99.0, 'ReversingLabs',      '2026-02-15 00:00:00', TRUE),
('ind-hsh-03', '7d793037a0760186574b0282f2f435e7bb71f9d4d98f000123456789abcdef01', '7d793037a0760186574b0282f2f435e7', 'BlackCat', 'ELF64',     'RANSOMWARE',  'act-wizard', 99.0, 'CISA-Alert',         '2026-05-12 00:00:00', TRUE)
ON CONFLICT (indicator_id) DO NOTHING;
