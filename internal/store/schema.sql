-- DNS Daddy schema. Applied idempotently at startup by store.Open.

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    categories  TEXT    NOT NULL DEFAULT '[]',
    block_mode  TEXT    NOT NULL DEFAULT 'nxdomain',
    safe_search INTEGER NOT NULL DEFAULT 0,
    log_queries INTEGER NOT NULL DEFAULT 1,
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id         INTEGER PRIMARY KEY,
    policy_id  TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('allow', 'block')),
    domain     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (policy_id, kind, domain)
);

CREATE TABLE IF NOT EXISTS networks (
    id         TEXT PRIMARY KEY,
    name       TEXT    NOT NULL,
    location   TEXT    NOT NULL DEFAULT '',
    policy_id  TEXT    NOT NULL REFERENCES policies(id),
    token      TEXT    UNIQUE,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS network_cidrs (
    id         INTEGER PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    cidr       TEXT NOT NULL,
    UNIQUE (network_id, cidr)
);

-- Operator-supplied friendly names for devices, so query logs read
-- "laptop-07" rather than "10.0.4.23".
CREATE TABLE IF NOT EXISTS clients (
    ip         TEXT PRIMARY KEY,
    name       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS feeds (
    id                TEXT PRIMARY KEY,
    name              TEXT    NOT NULL,
    url               TEXT    NOT NULL,
    category          TEXT    NOT NULL,
    format            TEXT    NOT NULL DEFAULT 'auto',
    enabled           INTEGER NOT NULL DEFAULT 1,
    builtin           INTEGER NOT NULL DEFAULT 0,
    domain_count      INTEGER NOT NULL DEFAULT 0,
    last_refreshed_at INTEGER,
    last_status       TEXT    NOT NULL DEFAULT '',
    last_error        TEXT    NOT NULL DEFAULT '',
    etag              TEXT    NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS query_log (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    client_ip   TEXT    NOT NULL DEFAULT '',
    client_name TEXT    NOT NULL DEFAULT '',
    network_id  TEXT    NOT NULL DEFAULT '',
    qname       TEXT    NOT NULL,
    qtype       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    category    TEXT    NOT NULL DEFAULT '',
    source      TEXT    NOT NULL DEFAULT '',
    proto       TEXT    NOT NULL DEFAULT '',
    elapsed_ms  INTEGER NOT NULL DEFAULT 0,
    cached      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS query_log_ts_idx        ON query_log (ts DESC);
CREATE INDEX IF NOT EXISTS query_log_action_ts_idx ON query_log (action, ts DESC);
CREATE INDEX IF NOT EXISTS query_log_network_idx   ON query_log (network_id, ts DESC);
CREATE INDEX IF NOT EXISTS query_log_qname_idx     ON query_log (qname);

-- Hourly rollups survive query-log pruning, so charts keep their history
-- even with a short log retention window.
CREATE TABLE IF NOT EXISTS stats_hourly (
    hour       INTEGER NOT NULL,
    network_id TEXT    NOT NULL,
    category   TEXT    NOT NULL,
    total      INTEGER NOT NULL DEFAULT 0,
    blocked    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, network_id, category)
);

CREATE TABLE IF NOT EXISTS blocked_domain_stats (
    day        INTEGER NOT NULL,
    domain     TEXT    NOT NULL,
    network_id TEXT    NOT NULL,
    category   TEXT    NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (day, domain, network_id)
);

CREATE INDEX IF NOT EXISTS blocked_domain_stats_day_idx ON blocked_domain_stats (day DESC, count DESC);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    hash         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
