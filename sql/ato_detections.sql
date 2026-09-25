-- Account-takeover and account-economy detections.
-- Engine-neutral SQL (window functions, CTEs). Schema assumed is the one documented in
-- apex-anticheat-lab/sql/schema.sql (players, hardware, player_hw, sessions, auth_events,
-- matches, match_players, enforcement) plus the two tables defined at the bottom of this file.
--
-- Each query names the signal from docs/signal-catalog.md that it implements.

-- ---------------------------------------------------------------------------
-- A1. Credential stuffing velocity
--     Signal: account DIVERSITY per source, not raw failure count.
-- ---------------------------------------------------------------------------
WITH src AS (
    SELECT ip_asn,
           COUNT(*)                                      AS attempts,
           COUNT(DISTINCT player_id)                     AS distinct_accounts,
           SUM(CASE WHEN success THEN 1 ELSE 0 END)      AS successes,
           MIN(ts) AS first_ts,
           MAX(ts) AS last_ts
    FROM auth_events
    WHERE kind = 'login'
      AND ts >= NOW() - INTERVAL '24 hours'
    GROUP BY ip_asn
)
SELECT ip_asn,
       attempts,
       distinct_accounts,
       successes,
       ROUND(100.0 * successes / NULLIF(attempts, 0), 3) AS success_rate_pct,
       ROUND(EXTRACT(EPOCH FROM (last_ts - first_ts)) / 60.0, 1) AS window_minutes,
       ROUND(attempts * 60.0 / NULLIF(EXTRACT(EPOCH FROM (last_ts - first_ts)), 0), 1) AS per_minute
FROM src
WHERE distinct_accounts >= 200                 -- many accounts, one source
  AND successes < attempts * 0.05              -- mostly failures
ORDER BY distinct_accounts DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- A3. Success-after-failure clustering
--     A login succeeds on an account that was just part of a failure burst.
-- ---------------------------------------------------------------------------
WITH bursts AS (
    SELECT player_id,
           COUNT(*)                            AS prior_failures,
           MAX(ts)                             AS last_failure
    FROM auth_events
    WHERE kind = 'login' AND success = FALSE
      AND ts >= NOW() - INTERVAL '7 days'
    GROUP BY player_id
    HAVING COUNT(*) >= 5
)
SELECT e.player_id,
       e.ts AS success_ts,
       b.prior_failures,
       b.last_failure,
       ROUND(EXTRACT(EPOCH FROM (e.ts - b.last_failure)) / 60.0, 1) AS minutes_since_failure
FROM auth_events e
JOIN bursts b ON b.player_id = e.player_id
WHERE e.kind = 'login' AND e.success = TRUE
  AND e.ts > b.last_failure
  AND e.ts < b.last_failure + INTERVAL '2 hours'
ORDER BY e.ts DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- A4. Impossible travel
--     Two successful logins from distant countries within a small interval.
-- ---------------------------------------------------------------------------
WITH ordered AS (
    SELECT player_id,
           ts,
           ip_country,
           ip_asn,
           LAG(ts)          OVER (PARTITION BY player_id ORDER BY ts) AS prev_ts,
           LAG(ip_country)  OVER (PARTITION BY player_id ORDER BY ts) AS prev_country
    FROM auth_events
    WHERE kind = 'login' AND success = TRUE
)
SELECT player_id,
       prev_country,
       ip_country,
       prev_ts,
       ts AS login_ts,
       ROUND(EXTRACT(EPOCH FROM (ts - prev_ts)) / 60.0, 1) AS gap_minutes
FROM ordered
WHERE prev_country IS NOT NULL
  AND prev_country IS DISTINCT FROM ip_country
  AND EXTRACT(EPOCH FROM (ts - prev_ts)) < 7200        -- < 2 hours
ORDER BY gap_minutes ASC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- A5. New device + immediate security change  (the takeover signature)
--     Sequence: first-seen device -> security change within N minutes.
-- ---------------------------------------------------------------------------
WITH first_seen AS (
    SELECT player_id,
           device_id,
           MIN(ts) AS first_ts
    FROM auth_events
    WHERE device_id IS NOT NULL
    GROUP BY player_id, device_id
    HAVING MIN(ts) >= NOW() - INTERVAL '14 days'
),
changes AS (
    SELECT player_id,
           ts,
           kind,
           ROW_NUMBER() OVER (PARTITION BY player_id ORDER BY ts) AS rn
    FROM auth_events
    WHERE kind IN ('email_change', 'password_change', 'mfa_disable', 'mfa_enroll', 'linked_platform_change')
)
SELECT f.player_id,
       f.device_id,
       f.first_ts,
       c.kind AS change_kind,
       c.ts   AS change_ts,
       ROUND(EXTRACT(EPOCH FROM (c.ts - f.first_ts)) / 60.0, 1) AS minutes_after_new_device
FROM first_seen f
JOIN changes c
  ON c.player_id = f.player_id
 AND c.ts >= f.first_ts
 AND c.ts <  f.first_ts + INTERVAL '60 minutes'
ORDER BY c.ts DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- A6. MFA downgrade followed by a new-context login
-- ---------------------------------------------------------------------------
WITH downgrades AS (
    SELECT player_id, ts AS downgrade_ts
    FROM auth_events
    WHERE kind IN ('mfa_disable', 'mfa_downgrade')
      AND ts >= NOW() - INTERVAL '14 days'
)
SELECT d.player_id,
       d.downgrade_ts,
       e.ts AS login_ts,
       e.device_id,
       e.ip_country,
       e.ip_asn,
       ROUND(EXTRACT(EPOCH FROM (e.ts - d.downgrade_ts)) / 60.0, 1) AS minutes_after_downgrade
FROM downgrades d
JOIN auth_events e
  ON e.player_id = d.player_id
 AND e.kind = 'login' AND e.success = TRUE
 AND e.ts BETWEEN d.downgrade_ts AND d.downgrade_ts + INTERVAL '24 hours'
WHERE e.device_id NOT IN (
        SELECT device_id FROM auth_events
        WHERE player_id = d.player_id AND ts < d.downgrade_ts AND device_id IS NOT NULL)
ORDER BY e.ts
LIMIT 200;

-- ---------------------------------------------------------------------------
-- B2. Concurrent session overlap with conflicting context
-- ---------------------------------------------------------------------------
SELECT a.player_id,
       a.session_id AS session_a,
       b.session_id AS session_b,
       a.started_at AS a_start,
       b.started_at AS b_start,
       a.ip_country AS a_country,
       b.ip_country AS b_country,
       a.hw_id      AS a_hw,
       b.hw_id      AS b_hw
FROM sessions a
JOIN sessions b
  ON b.player_id = a.player_id
 AND b.session_id > a.session_id
 AND b.started_at < COALESCE(a.ended_at, NOW())
 AND a.started_at < COALESCE(b.ended_at, NOW())
WHERE a.ip_country IS DISTINCT FROM b.ip_country
   OR a.hw_id IS DISTINCT FROM b.hw_id
LIMIT 200;

-- ---------------------------------------------------------------------------
-- C1. Hardware fingerprint churn per account
-- ---------------------------------------------------------------------------
SELECT ph.player_id,
       COUNT(DISTINCT ph.hw_id)            AS distinct_hardware,
       MIN(ph.first_seen)                  AS first_seen,
       MAX(ph.last_seen)                   AS last_seen,
       ROUND(EXTRACT(EPOCH FROM (MAX(ph.last_seen) - MIN(ph.first_seen))) / 86400.0, 1) AS span_days
FROM player_hw ph
JOIN players p ON p.player_id = ph.player_id
WHERE p.account_created >= NOW() - INTERVAL '60 days'
GROUP BY ph.player_id
HAVING COUNT(DISTINCT ph.hw_id) >= 3
ORDER BY distinct_hardware DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- C2. Fingerprint internal inconsistency (spoofing indicator)
-- ---------------------------------------------------------------------------
SELECT h.hw_id,
       h.fingerprint,
       COUNT(DISTINCT h.mb_uuid)     AS distinct_mb_uuid,
       COUNT(DISTINCT h.disk_serial) AS distinct_disk_serial,
       COUNT(DISTINCT h.mac_vendor)  AS distinct_mac_vendors
FROM hardware h
GROUP BY h.hw_id, h.fingerprint
HAVING COUNT(DISTINCT h.mb_uuid) > 1
    OR COUNT(DISTINCT h.disk_serial) > 2
    OR COUNT(DISTINCT h.mac_vendor) > 2
ORDER BY distinct_disk_serial DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- C3. New account on previously banned hardware
-- ---------------------------------------------------------------------------
SELECT p.player_id AS new_player,
       p.account_created,
       h.fingerprint,
       b.player_id AS prior_banned_player,
       b.banned_at,
       ROUND(EXTRACT(EPOCH FROM (p.account_created - b.banned_at)) / 3600.0, 1) AS hours_after_ban
FROM players p
JOIN player_hw ph  ON ph.player_id = p.player_id
JOIN hardware  h   ON h.hw_id = ph.hw_id
JOIN player_hw ph2 ON ph2.hw_id = h.hw_id
JOIN players   b   ON b.player_id = ph2.player_id AND b.is_banned
WHERE p.player_id <> b.player_id
  AND p.account_created > b.banned_at
  AND NOT p.is_banned
ORDER BY p.account_created DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- D2. Skill vs. account age mismatch
--     Review signal only. Never action on its own.
-- ---------------------------------------------------------------------------
SELECT p.player_id,
       p.account_level,
       ROUND(EXTRACT(EPOCH FROM (NOW() - p.account_created)) / 86400.0, 1) AS age_days,
       COUNT(mp.match_id) AS matches,
       ROUND(AVG(mp.kills), 2)   AS avg_kills,
       ROUND(AVG(mp.damage), 1)  AS avg_damage,
       MAX(p.rank_tier) AS tier
FROM players p
JOIN match_players mp ON mp.player_id = p.player_id
WHERE p.account_created >= NOW() - INTERVAL '30 days'
GROUP BY p.player_id, p.account_level, p.account_created
HAVING COUNT(mp.match_id) >= 20
   AND AVG(mp.kills) > 6
ORDER BY avg_kills DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- E1. Asymmetric duo (boosting / deranking delivery)
-- ---------------------------------------------------------------------------
WITH duos AS (
    SELECT a.player_id AS high_performer,
           b.player_id AS partner
    FROM match_players a
    JOIN match_players b
      ON b.match_id = a.match_id
     AND b.squad_id = a.squad_id
     AND b.player_id <> a.player_id
    GROUP BY a.player_id, b.player_id
    HAVING COUNT(*) >= 20
),
perf AS (
    SELECT player_id,
           AVG(kills + assists) AS avg_ka,
           AVG(rp_delta)        AS avg_rp
    FROM match_players
    GROUP BY player_id
)
SELECT d.high_performer,
       d.partner,
       ROUND(p1.avg_ka, 2) AS high_ka,
       ROUND(p2.avg_ka, 2) AS partner_ka,
       ROUND(p1.avg_rp, 1) AS high_rp,
       ROUND(p2.avg_rp, 1) AS partner_rp
FROM duos d
JOIN perf p1 ON p1.player_id = d.high_performer
JOIN perf p2 ON p2.player_id = d.partner
WHERE p1.avg_ka > 2.5 * NULLIF(p2.avg_ka, 0)
  AND p2.avg_rp > 0
ORDER BY high_ka DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- E4. Payment fraud correlation
--     Requires the `payments` table below.
-- ---------------------------------------------------------------------------
SELECT p.player_id,
       p.account_created,
       COUNT(*) FILTER (WHERE pay.status = 'chargeback') AS chargebacks,
       COUNT(*) AS payments,
       ROUND(100.0 * COUNT(*) FILTER (WHERE pay.status = 'chargeback') / COUNT(*), 1) AS cb_rate_pct
FROM players p
JOIN payments pay ON pay.player_id = p.player_id
GROUP BY p.player_id, p.account_created
HAVING COUNT(*) >= 3
   AND COUNT(*) FILTER (WHERE pay.status = 'chargeback') >= 2
ORDER BY chargebacks DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- Breadth triage: rank accounts by INDEPENDENT signal count.
-- Three moderate signals beat one extreme one, and are far easier to defend on appeal.
-- ---------------------------------------------------------------------------
WITH signals AS (
    -- A5: new device + security change
    SELECT DISTINCT player_id, 'new_device_security_change' AS signal
    FROM auth_events WHERE kind IN ('email_change','password_change','mfa_disable')

    UNION ALL
    -- C3: banned-identity reuse
    SELECT DISTINCT p.player_id, 'banned_hw_reuse'
    FROM players p
    JOIN player_hw ph  ON ph.player_id = p.player_id
    JOIN player_hw ph2 ON ph2.hw_id = ph.hw_id
    JOIN players   b   ON b.player_id = ph2.player_id AND b.is_banned
    WHERE p.player_id <> b.player_id AND p.account_created > b.banned_at

    UNION ALL
    -- C1: hardware churn
    SELECT player_id, 'hardware_churn'
    FROM player_hw GROUP BY player_id HAVING COUNT(DISTINCT hw_id) >= 3

    UNION ALL
    -- D2: skill vs age
    SELECT p.player_id, 'skill_age_mismatch'
    FROM players p JOIN match_players mp ON mp.player_id = p.player_id
    WHERE p.account_created >= NOW() - INTERVAL '30 days'
    GROUP BY p.player_id, p.account_created
    HAVING COUNT(mp.match_id) >= 20 AND AVG(mp.kills) > 6

    UNION ALL
    -- B2: concurrent conflicting sessions
    SELECT a.player_id, 'concurrent_conflicting_sessions'
    FROM sessions a JOIN sessions b
      ON b.player_id = a.player_id AND b.session_id > a.session_id
     AND b.started_at < COALESCE(a.ended_at, NOW())
     AND a.started_at < COALESCE(b.ended_at, NOW())
    WHERE a.ip_country IS DISTINCT FROM b.ip_country
)
SELECT player_id,
       COUNT(DISTINCT signal) AS independent_signals,
       STRING_AGG(DISTINCT signal, ', ' ORDER BY signal) AS signals
FROM signals
GROUP BY player_id
HAVING COUNT(DISTINCT signal) >= 2
ORDER BY independent_signals DESC
LIMIT 500;

-- ---------------------------------------------------------------------------
-- Supporting tables referenced above
-- ---------------------------------------------------------------------------
CREATE TABLE payments (
    payment_id   BIGINT PRIMARY KEY,
    player_id    BIGINT,
    ts           TIMESTAMP NOT NULL,
    amount_cents INT,
    currency     TEXT,
    instrument   TEXT,          -- card / wallet / carrier / gift
    status       TEXT,          -- settled / refunded / chargeback / failed
    country      TEXT
);

-- Extension to auth_events kinds used by these detections:
--   login, logout, token_refresh, password_reset, password_change, email_change,
--   mfa_enroll, mfa_disable, mfa_downgrade, linked_platform_change
