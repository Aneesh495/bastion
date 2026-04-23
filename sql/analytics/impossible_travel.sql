-- ============================================================================
-- BASTION: ZERO-TRUST IDENTITY GRAPH AND THREAT DETECTION KERNEL
-- File: sql/analytics/impossible_travel.sql
-- Description: Impossible travel velocity calculations, Haversine geodesic
--              distance modeling, and compromised session concurrency in ANSI SQL.
-- Dialect: ANSI SQL / DuckDB / PostgreSQL
-- Copyright 2026 Aneesh Krishna Parthasarathy. Apache License 2.0.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Sequential Authentication Geolocation Pairing
-- ----------------------------------------------------------------------------
-- Pairs consecutive successful authentications for the same user identity and
-- computes spatial and temporal deltas:
--   Delta_t = t_2 - t_1 (in hours)
--   Distance = Great Circle Distance (in kilometers)
--   Velocity = Distance / Delta_t (in km/h)
-- Commercial aircraft maximum cruising velocity ~= 950 km/h.
-- Any velocity exceeding 1,000 km/h is physically impossible.
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_sequential_user_logins AS
WITH valid_geo_auths AS (
    SELECT
        auth_event_id,
        principal_id,
        username_asserted,
        source_ip,
        source_country,
        source_city,
        source_latitude,
        source_longitude,
        event_time
    FROM telemetry_authentication_events
    WHERE auth_status = 'SUCCESS'
      AND source_latitude IS NOT NULL
      AND source_longitude IS NOT NULL
),
paired_events AS (
    SELECT
        auth_event_id AS current_event_id,
        principal_id,
        username_asserted,
        source_ip AS current_ip,
        source_country AS current_country,
        source_city AS current_city,
        source_latitude AS lat2,
        source_longitude AS lon2,
        event_time AS current_time,
        LAG(auth_event_id, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_event_id,
        LAG(source_ip, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_ip,
        LAG(source_country, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_country,
        LAG(source_city, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_city,
        LAG(source_latitude, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS lat1,
        LAG(source_longitude, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS lon1,
        LAG(event_time, 1) OVER (PARTITION BY username_asserted ORDER BY event_time) AS prev_time
    FROM valid_geo_auths
)
SELECT
    current_event_id,
    prev_event_id,
    principal_id,
    username_asserted,
    prev_ip,
    prev_city,
    prev_country,
    current_ip,
    current_city,
    current_country,
    prev_time,
    current_time,
    -- Time delta in hours (minimum 0.001 to prevent division by zero)
    GREATEST(0.001, EXTRACT(EPOCH FROM (current_time - prev_time)) / 3600.0) AS delta_hours,
    -- Degrees to radians multiplier: pi / 180 = 0.017453292519943295
    -- Spherical Law of Cosines Distance approximation in km (Earth radius = 6371 km)
    6371.0 * ACOS(
        GREATEST(-1.0, LEAST(1.0,
            SIN(lat1 * 0.0174532925) * SIN(lat2 * 0.0174532925) +
            COS(lat1 * 0.0174532925) * COS(lat2 * 0.0174532925) *
            COS((lon2 - lon1) * 0.0174532925)
        ))
    ) AS geodesic_distance_km
FROM paired_events
WHERE prev_time IS NOT NULL
  AND current_ip <> prev_ip;

-- ----------------------------------------------------------------------------
-- 2. Impossible Travel Velocity Threshold Model
-- ----------------------------------------------------------------------------

CREATE VIEW IF NOT EXISTS v_impossible_travel_violations AS
SELECT
    current_event_id,
    prev_event_id,
    principal_id,
    username_asserted,
    prev_ip,
    prev_city || ', ' || prev_country AS previous_location,
    current_ip,
    current_city || ', ' || current_country AS current_location,
    prev_time,
    current_time,
    delta_hours,
    geodesic_distance_km,
    (geodesic_distance_km / delta_hours) AS calculated_velocity_kmh,
    CASE
        WHEN (geodesic_distance_km / delta_hours) >= 1200.0 THEN 'IMPOSSIBLE_SUPERSONIC_TRAVEL'
        WHEN (geodesic_distance_km / delta_hours) >= 800.0  THEN 'SUSPICIOUS_HIGH_SPEED_TRANSIT'
        ELSE 'PLAUSIBLE_TRAVEL'
    END AS travel_classification,
    CASE
        WHEN (geodesic_distance_km / delta_hours) >= 1200.0 THEN 98.0
        WHEN (geodesic_distance_km / delta_hours) >= 800.0  THEN 85.0
        ELSE 10.0
    END AS velocity_confidence_score
FROM v_sequential_user_logins
WHERE geodesic_distance_km >= 250.0 -- Ignore micro-movements within same metro area
ORDER BY calculated_velocity_kmh DESC;
