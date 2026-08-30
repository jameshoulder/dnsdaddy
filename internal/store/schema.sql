-- DNS Daddy schema. Applied idempotently at startup by store.Open.

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Dashboard sessions.
--
-- The session cookie used to be a self-contained "<expiry>.<hmac(expiry)>",
-- which meant the server held no opinion about any particular session: logout
-- could only ask the browser to forget it, a password change left every live
-- session working, and anyone holding the signing key could mint a valid
-- cookie for any expiry they liked, forever. Moving the state here is what
-- makes "log out", "change the password", and "revoke everything" mean
-- something on the server rather than only in the browser.
--
-- token_hash, not token: this table is in the same SQLite file as the query
-- log and the feed cache, and a database that leaks should not hand over live
-- sessions with it. The cookie carries the only copy of the secret, and the
-- server stores SHA-256 of it. A plain hash is right here where bcrypt is not:
-- the input is 256 bits from crypto/rand, so there is no guessing to slow
-- down, and login latency would suffer for nothing.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    label       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

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
    -- Whether this network's addresses may query the resolver at all, as
    -- opposed to which policy they get once admitted. Defaults to 0 so an
    -- upgrade grants nobody anything they did not already have: the
    -- bootstrap ACL keeps working exactly as it did. See internal/clientacl.
    allow_resolver INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS network_cidrs (
    id         INTEGER PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    cidr       TEXT NOT NULL,
    -- Records that an operator affirmed this specific publicly routable range.
    -- Kept per CIDR, not per network, so an unrelated later edit does not
    -- re-prompt for a range already acknowledged, while adding a *new* public
    -- range does.
    public_ack INTEGER NOT NULL DEFAULT 0,
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
    last_success_at   INTEGER,
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
    cached      INTEGER NOT NULL DEFAULT 0,
    -- DNSSEC validation status reported by the upstream resolver:
    -- 'validated', 'unvalidated', 'servfail', or '' where no upstream was
    -- consulted. DNS Daddy forwards rather than validating locally, so this
    -- records what the upstream concluded. See docs/dnssec.md.
    dnssec      TEXT    NOT NULL DEFAULT ''
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

-- Behavioural security findings from internal/detect.
--
-- The full finding document is stored as JSON in `detail` and the fields worth
-- filtering on are lifted into columns. That keeps the schema stable as the
-- finding format grows: adding a signal or a piece of evidence changes the
-- JSON and needs no migration, while the columns an operator actually queries
-- on stay indexed.
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    ts          INTEGER NOT NULL,
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    confidence  REAL    NOT NULL DEFAULT 0,
    score       REAL    NOT NULL DEFAULT 0,
    client_ip   TEXT    NOT NULL DEFAULT '',
    client_name TEXT    NOT NULL DEFAULT '',
    network_id  TEXT    NOT NULL DEFAULT '',
    domain      TEXT    NOT NULL DEFAULT '',
    qtype       TEXT    NOT NULL DEFAULT '',
    detector    TEXT    NOT NULL DEFAULT '',
    title       TEXT    NOT NULL DEFAULT '',
    summary     TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS findings_ts_idx       ON findings (ts DESC);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings (severity, ts DESC);
CREATE INDEX IF NOT EXISTS findings_type_idx     ON findings (event_type, ts DESC);
CREATE INDEX IF NOT EXISTS findings_client_idx   ON findings (client_ip, ts DESC);
