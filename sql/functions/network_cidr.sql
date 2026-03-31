-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/functions/network_cidr.sql
-- Description: IPv4 and IPv6 CIDR arithmetic, integer conversions, subnet
--              containment verification, and RFC-1918 / Cloud Metadata classification.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. IPv4 Octet Deconstruction and 32-Bit Integer Representation
-- ----------------------------------------------------------------------------
-- Translates dotted-quad IPv4 string "A.B.C.D" into an unsigned 32-bit integer:
--   IP_INT = (A * 256^3) + (B * 256^2) + (C * 256) + D
-- This enables single-cycle range checks for subnet containment:
--   CIDR_START <= IP_INT <= CIDR_END
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_parsed_flow_ips AS
WITH split_ips AS (
    SELECT
        flow_id,
        src_addr,
        dst_addr,
        dst_port,
        protocol,
        bytes_transferred,
        action,
        start_time,
        -- Extract octets for source IP
        CAST(SPLIT_PART(src_addr, '.', 1) AS BIGINT) AS src_o1,
        CAST(SPLIT_PART(src_addr, '.', 2) AS BIGINT) AS src_o2,
        CAST(SPLIT_PART(src_addr, '.', 3) AS BIGINT) AS src_o3,
        CAST(SPLIT_PART(src_addr, '.', 4) AS BIGINT) AS src_o4,
        -- Extract octets for destination IP
        CAST(SPLIT_PART(dst_addr, '.', 1) AS BIGINT) AS dst_o1,
        CAST(SPLIT_PART(dst_addr, '.', 2) AS BIGINT) AS dst_o2,
        CAST(SPLIT_PART(dst_addr, '.', 3) AS BIGINT) AS dst_o3,
        CAST(SPLIT_PART(dst_addr, '.', 4) AS BIGINT) AS dst_o4
    FROM telemetry_vpc_flow_logs
    WHERE src_addr LIKE '%.%.%.%' AND dst_addr LIKE '%.%.%.%'
)
SELECT
    flow_id,
    src_addr,
    dst_addr,
    dst_port,
    protocol,
    bytes_transferred,
    action,
    start_time,
    -- Compute 32-bit integer representations
    (src_o1 * 16777216 + src_o2 * 65536 + src_o3 * 256 + src_o4) AS src_ip_int,
    (dst_o1 * 16777216 + dst_o2 * 65536 + dst_o3 * 256 + dst_o4) AS dst_ip_int,
    -- RFC 1918 Private Address Space Classification
    CASE
        WHEN src_o1 = 10 THEN 'RFC1918_10'
        WHEN src_o1 = 172 AND src_o2 BETWEEN 16 AND 31 THEN 'RFC1918_172'
        WHEN src_o1 = 192 AND src_o2 = 168 THEN 'RFC1918_192'
        WHEN src_o1 = 127 THEN 'LOOPBACK'
        WHEN src_o1 = 169 AND src_o2 = 254 THEN 'LINK_LOCAL'
        ELSE 'PUBLIC_INTERNET'
    END AS src_zone,
    CASE
        WHEN dst_o1 = 10 THEN 'RFC1918_10'
        WHEN dst_o1 = 172 AND dst_o2 BETWEEN 16 AND 31 THEN 'RFC1918_172'
        WHEN dst_o1 = 192 AND dst_o2 = 168 THEN 'RFC1918_192'
        WHEN dst_o1 = 127 THEN 'LOOPBACK'
        WHEN dst_o1 = 169 AND dst_o2 = 254 AND dst_o3 = 169 AND dst_o4 = 254 THEN 'CLOUD_METADATA_SERVICE'
        WHEN dst_o1 = 169 AND dst_o2 = 254 THEN 'LINK_LOCAL'
        ELSE 'PUBLIC_INTERNET'
    END AS dst_zone
FROM split_ips;

-- ----------------------------------------------------------------------------
-- 2. Subnet CIDR Block Range Pre-Computation
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_subnet_ip_ranges AS
WITH subnet_tokens AS (
    SELECT
        subnet_id,
        vnet_id,
        subnet_name,
        zone_type,
        cidr_block,
        SPLIT_PART(cidr_block, '/', 1) AS ip_part,
        CAST(SPLIT_PART(cidr_block, '/', 2) AS INTEGER) AS prefix_len
    FROM core_subnets
),
subnet_octets AS (
    SELECT
        subnet_id,
        vnet_id,
        subnet_name,
        zone_type,
        cidr_block,
        prefix_len,
        CAST(SPLIT_PART(ip_part, '.', 1) AS BIGINT) AS o1,
        CAST(SPLIT_PART(ip_part, '.', 2) AS BIGINT) AS o2,
        CAST(SPLIT_PART(ip_part, '.', 3) AS BIGINT) AS o3,
        CAST(SPLIT_PART(ip_part, '.', 4) AS BIGINT) AS o4
    FROM subnet_tokens
)
SELECT
    subnet_id,
    vnet_id,
    subnet_name,
    zone_type,
    cidr_block,
    prefix_len,
    (o1 * 16777216 + o2 * 65536 + o3 * 256 + o4) AS start_ip_int,
    -- Range span = 2^(32 - prefix) - 1
    (o1 * 16777216 + o2 * 65536 + o3 * 256 + o4) + CAST(POWER(2, 32 - prefix_len) - 1 AS BIGINT) AS end_ip_int
FROM subnet_octets;

-- ----------------------------------------------------------------------------
-- 3. Dynamic Flow Containment and Perimeter Crossing Classification
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_perimeter_crossing_flows AS
SELECT
    f.flow_id,
    f.src_addr,
    f.dst_addr,
    f.dst_port,
    f.bytes_transferred,
    f.action,
    f.start_time,
    f.src_zone,
    f.dst_zone,
    src_sub.subnet_name AS src_subnet,
    src_sub.zone_type AS src_zone_type,
    dst_sub.subnet_name AS dst_subnet,
    dst_sub.zone_type AS dst_zone_type,
    CASE
        WHEN f.dst_zone = 'CLOUD_METADATA_SERVICE' THEN 'METADATA_SERVICE_ACCESS'
        WHEN f.src_zone = 'PUBLIC_INTERNET' AND f.dst_zone <> 'PUBLIC_INTERNET' THEN 'INGRESS_FROM_INTERNET'
        WHEN f.src_zone <> 'PUBLIC_INTERNET' AND f.dst_zone = 'PUBLIC_INTERNET' THEN 'EGRESS_TO_INTERNET'
        WHEN src_sub.zone_type = 'DMZ' AND dst_sub.zone_type = 'DATA' THEN 'DMZ_TO_DATA_TRANSIT'
        WHEN src_sub.zone_type = 'DATA' AND dst_sub.zone_type <> 'DATA' THEN 'DATA_ZONE_CROSSING'
        ELSE 'INTRA_ZONE'
    END AS traffic_boundary_classification
FROM v_parsed_flow_ips f
LEFT JOIN v_subnet_ip_ranges src_sub
  ON f.src_ip_int >= src_sub.start_ip_int AND f.src_ip_int <= src_sub.end_ip_int
LEFT JOIN v_subnet_ip_ranges dst_sub
  ON f.dst_ip_int >= dst_sub.start_ip_int AND f.dst_ip_int <= dst_sub.end_ip_int;
