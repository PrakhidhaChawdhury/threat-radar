import sqlite3

con = sqlite3.connect("threat_radar.db")

migrations = [
    ("audit_status", "ALTER TABLE threat_reports ADD COLUMN audit_status TEXT NOT NULL DEFAULT 'VERIFIED'"),
    ("audit_corrections", "ALTER TABLE threat_reports ADD COLUMN audit_corrections TEXT"),
]

for label, sql in migrations:
    try:
        con.execute(sql)
        print(f"Added column: {label}")
    except Exception as e:
        print(f"Skipped {label}: {e}")

con.commit()
con.close()
print("Migration complete.")
