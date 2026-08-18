-- ─────────────────────────────────────────────────────────────
-- Threat Radar — SQLite Schema
-- 3 clean tables, zero over-engineering
-- ─────────────────────────────────────────────────────────────

-- 1. Raw scraped items — primary deduplication layer
--    Every URL we have ever seen lives here. If it's in here, we skip it.
CREATE TABLE IF NOT EXISTS scraped_items (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name     TEXT    NOT NULL,               -- e.g. "reddit_scams", "github_advisories"
    source_url      TEXT    NOT NULL UNIQUE,         -- The full canonical URL of the item
    url_hash        TEXT    NOT NULL UNIQUE,         -- SHA-256 of source_url (fast index lookup)
    raw_title       TEXT,
    raw_content     TEXT,
    status          TEXT    NOT NULL DEFAULT 'PENDING',  -- PENDING | SKIPPED_BENIGN | FAILED_PARSING | ANALYZED
    scraped_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Structured threat intelligence reports produced by Gemini
--    Only rows where Gemini's analysis passed Pydantic validation end up here
CREATE TABLE IF NOT EXISTS threat_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id         INTEGER NOT NULL UNIQUE,
    source_intent   TEXT    NOT NULL,   -- ACTIVE_LURE | VICTIM_REPORT | EDUCATIONAL_ADVISORY | UNKNOWN_DISCUSSION
    risk_level      TEXT    NOT NULL,   -- CRITICAL | HIGH | MEDIUM | LOW | BENIGN
    threat_category TEXT    NOT NULL,
    threat_title    TEXT    NOT NULL,
    the_lure        TEXT,
    the_hidden_trap TEXT,
    red_flags       TEXT,               -- JSON string array: ["flag1", "flag2"]
    action_checklist TEXT,              -- JSON string array: ["step1", "step2", "step3"]
    relevance_score INTEGER NOT NULL,   -- 1-10 for User Zero
    confidence_score REAL   NOT NULL,   -- 0.0-1.0
    unmatched_reason TEXT,              -- populated when confidence < floor
    notified        INTEGER NOT NULL DEFAULT 0,  -- 1 = Discord alert was sent
    analyzed_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(item_id) REFERENCES scraped_items(id)
);

-- 3. Scraper health and self-healing telemetry
--    Every scrape attempt is logged here for the dashboard health panel
CREATE TABLE IF NOT EXISTS scraper_telemetry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    collector_id    TEXT    NOT NULL,
    source_name     TEXT    NOT NULL,
    target_url      TEXT    NOT NULL,
    status          TEXT    NOT NULL,   -- HEALTHY | DEGRADED | HEALING | HEALED | FAILED
    error_message   TEXT,               -- populated on DEGRADED / FAILED
    items_found     INTEGER DEFAULT 0,
    items_new       INTEGER DEFAULT 0,
    heal_triggered  INTEGER DEFAULT 0,  -- 1 = self-heal was triggered this cycle
    healed_at       TIMESTAMP,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
