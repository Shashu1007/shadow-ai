-- DPDP Drift Scanner — schema
-- Matches the data model in the MVP spec: clients / scans / findings / diffs

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS clients (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT NOT NULL UNIQUE,
    whatsapp_number TEXT,
    plan_tier       TEXT NOT NULL DEFAULT 'trial',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id         INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scanned_at        TEXT NOT NULL DEFAULT (datetime('now')),
    page_count        INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL DEFAULT 'completed',  -- running | completed | failed
    raw_findings_json TEXT  -- full raw crawl+classification payload, for audit trail
);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    page_url            TEXT NOT NULL,
    type                TEXT NOT NULL,   -- form_field | cookie | third_party_script | consent_banner | privacy_policy
    detail              TEXT NOT NULL,   -- human-readable detail, e.g. "input name=phone, label=Mobile Number"
    detail_hash         TEXT NOT NULL,   -- hash(type + domain/url + normalized field/detail key) — diff match key
    data_category       TEXT,            -- contact | financial | health | children | behavioral | identity | none
    third_party_domain  TEXT,
    dpdp_relevance      TEXT,            -- notice | consent | security_safeguard | children_data | cross_border_transfer | none
    confidence          TEXT NOT NULL DEFAULT 'medium',  -- high | medium | low
    raw_json            TEXT             -- full classifier finding object
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(detail_hash);

CREATE TABLE IF NOT EXISTS diffs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    prev_scan_id  INTEGER REFERENCES scans(id),
    curr_scan_id  INTEGER NOT NULL REFERENCES scans(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    new_json      TEXT NOT NULL DEFAULT '[]',
    changed_json  TEXT NOT NULL DEFAULT '[]',
    removed_json  TEXT NOT NULL DEFAULT '[]',
    severity      TEXT NOT NULL DEFAULT 'low'  -- high | medium | low — max severity across the diff
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    diff_id       INTEGER NOT NULL REFERENCES diffs(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    severity      TEXT NOT NULL,
    channel       TEXT NOT NULL DEFAULT 'whatsapp_sim',  -- whatsapp_sim | whatsapp | dashboard
    message       TEXT NOT NULL,       -- rendered WhatsApp-style alert text
    status        TEXT NOT NULL DEFAULT 'open'  -- open | handled
);

-- Human review queue for low-confidence classifier findings — never shown to client directly
CREATE TABLE IF NOT EXISTS review_queue (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    client_id     INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    status        TEXT NOT NULL DEFAULT 'pending'  -- pending | approved | rejected
);

-- Auto-drafted (never auto-published) notice paragraphs and data-inventory rows
CREATE TABLE IF NOT EXISTS drafts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    finding_id    INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    kind          TEXT NOT NULL,  -- notice_paragraph | inventory_row
    content       TEXT NOT NULL,  -- text (notice) or JSON (inventory row: field, purpose, vendor, retention)
    status        TEXT NOT NULL DEFAULT 'draft'  -- draft | approved | rejected
);
