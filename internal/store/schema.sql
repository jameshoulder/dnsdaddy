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

-- ---------------------------------------------------------------------------
-- External API providers: "bring your own intelligence".
--
-- Configuration and credentials are deliberately two tables. A SELECT * on
-- api_providers — in a debug handler, a backup script, an ad-hoc sqlite3
-- session — cannot pick up a credential by accident, because there is no
-- credential in it to pick up. See docs/external-apis.md.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS api_providers (
    id                TEXT PRIMARY KEY,
    name              TEXT    NOT NULL,
    -- Registry key naming the adapter: safebrowsing, virustotal, customhttp.
    kind              TEXT    NOT NULL,
    enabled           INTEGER NOT NULL DEFAULT 0,
    -- JSON array of the capabilities the operator switched on, which is a
    -- subset of what the adapter can do. Enabling a provider is not the same
    -- decision as letting it influence resolution.
    capabilities      TEXT    NOT NULL DEFAULT '[]',
    -- JSON object of adapter-specific NON-SECRET settings: endpoint, field
    -- paths, header names. Anything secret belongs in api_provider_secrets.
    config            TEXT    NOT NULL DEFAULT '{}',
    timeout_ms        INTEGER NOT NULL DEFAULT 2000,
    rate_per_minute   INTEGER NOT NULL DEFAULT 60,
    cache_ttl_seconds INTEGER NOT NULL DEFAULT 21600,
    -- JSON array of policy IDs this provider applies to. Empty means every
    -- policy, which is the common case; naming policies is how a guest VLAN
    -- gets live reputation while a finance VLAN does not.
    policy_scope      TEXT    NOT NULL DEFAULT '[]',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

-- The credential, sealed with AES-256-GCM by internal/secrets.
--
-- ciphertext is nonce ‖ sealed, and the provider id is the additional
-- authenticated data, so a row moved between providers fails to open rather
-- than silently authenticating one service with another's key.
--
-- hint is the last four characters of the plaintext. It exists so the
-- dashboard can say WHICH credential is stored without showing it, which is
-- what every vendor console does and is far too little to narrow a search.
CREATE TABLE IF NOT EXISTS api_provider_secrets (
    provider_id TEXT PRIMARY KEY REFERENCES api_providers(id) ON DELETE CASCADE,
    ciphertext  BLOB    NOT NULL,
    key_id      TEXT    NOT NULL DEFAULT '',
    hint        TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    rotated_at  INTEGER
);

-- Reputation answers, cached across restarts.
--
-- Persisted because a restart on a small VPS should not re-ask a metered API
-- about every domain the network resolves in its first ten minutes. Pruned on
-- the same schedule as the query log.
CREATE TABLE IF NOT EXISTS intel_verdicts (
    subject     TEXT    NOT NULL,
    provider_id TEXT    NOT NULL REFERENCES api_providers(id) ON DELETE CASCADE,
    score       REAL    NOT NULL DEFAULT 0,
    -- malicious | suspicious | benign | unknown
    disposition TEXT    NOT NULL DEFAULT 'unknown',
    categories  TEXT    NOT NULL DEFAULT '[]',
    -- A bounded excerpt of the provider's own answer, so an operator can see
    -- what a verdict was actually based on rather than trusting our
    -- normalisation of it.
    raw         TEXT    NOT NULL DEFAULT '',
    fetched_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (subject, provider_id)
);

CREATE INDEX IF NOT EXISTS intel_verdicts_expiry_idx ON intel_verdicts (expires_at);

-- Context added to query-log rows and findings. Never a judgement, and never
-- consulted by the resolution path.
CREATE TABLE IF NOT EXISTS intel_enrichment (
    subject     TEXT    NOT NULL,
    provider_id TEXT    NOT NULL REFERENCES api_providers(id) ON DELETE CASCADE,
    data        TEXT    NOT NULL DEFAULT '{}',
    fetched_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (subject, provider_id)
);

CREATE INDEX IF NOT EXISTS intel_enrichment_expiry_idx ON intel_enrichment (expires_at);
