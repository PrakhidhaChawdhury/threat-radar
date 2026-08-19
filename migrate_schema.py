import sqlite3

con = sqlite3.connect("threat_radar.db")

migrations = [
    ("campaign_id", "ALTER TABLE threat_reports ADD COLUMN campaign_id INTEGER REFERENCES threat_campaigns(id)"),
    ("campaign_fingerprint", "ALTER TABLE threat_reports ADD COLUMN campaign_fingerprint TEXT"),
    ("extracted_entities", "ALTER TABLE threat_reports ADD COLUMN extracted_entities TEXT"),
]

for label, sql in migrations:
    try:
        con.execute(sql)
        print(f"Added column: {label}")
    except Exception as e:
        print(f"Skipped {label}: {e}")

# Also ensure threat_campaigns table exists
con.execute("""
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_fingerprint TEXT NOT NULL UNIQUE,
    canonical_name      TEXT NOT NULL,
    threat_category     TEXT NOT NULL,
    risk_level          TEXT NOT NULL,
    report_count        INTEGER NOT NULL DEFAULT 1,
    velocity            TEXT NOT NULL DEFAULT 'NEW',
    first_seen          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

con.commit()
con.close()
print("Migration completed successfully.")
