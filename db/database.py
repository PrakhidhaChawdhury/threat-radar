"""
db/database.py — Async SQLite layer.
Handles: init, deduplication checks, saves, and telemetry logging.
"""

from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path

import aiosqlite

from config import DATABASE_PATH

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


@asynccontextmanager
async def get_db():
    """Async context manager for SQLite connections."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        yield db


async def init_db() -> None:
    """Create all tables from schema.sql if they don't already exist."""
    schema = _SCHEMA_PATH.read_text(encoding="utf-8")
    async with get_db() as db:
        await db.executescript(schema)
        await db.commit()
    print("[DB] Database initialized.")


def make_url_hash(url: str) -> str:
    """SHA-256 hash of a URL — used as the fast dedup lookup key."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


async def is_url_seen(url: str) -> bool:
    """Returns True if this URL has already been scraped."""
    url_hash = make_url_hash(url)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT 1 FROM scraped_items WHERE url_hash = ?", (url_hash,)
        )
        row = await cursor.fetchone()
        return row is not None


async def save_scraped_item(
    source_name: str,
    source_url: str,
    raw_title: str | None,
    raw_content: str | None,
    status: str = "PENDING",
) -> int:
    """
    Persist a new scraped item to the database.
    Returns the new row ID. Raises sqlite3.IntegrityError if URL already exists.
    """
    url_hash = make_url_hash(source_url)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO scraped_items (source_name, source_url, url_hash, raw_title, raw_content, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (source_name, source_url, url_hash, raw_title, raw_content, status),
        )
        await db.commit()
        return cursor.lastrowid


async def update_scraped_item_status(item_id: int, status: str) -> None:
    """Update the processing status of a scraped item."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE scraped_items SET status = ? WHERE id = ?",
            (status, item_id),
        )
        await db.commit()


async def save_threat_report(
    item_id: int,
    payload: dict,
    audit_status: str = "VERIFIED",
    audit_corrections: list | None = None,
) -> tuple[int, int, str]:
    """
    Persist a structured Gemini analysis to threat_reports and cluster into threat_campaigns.
    Returns tuple: (report_id, campaign_id, campaign_velocity).
    """
    fingerprint = payload.get("campaign_fingerprint", "UNKNOWN_CAMPAIGN").strip().upper()
    category = payload["threat_category"]
    risk = payload["risk_level"]
    canonical_name = payload["threat_title"]

    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row

        # ── Step A: Upsert Campaign Cluster ───────────────────
        cur = await db.execute(
            "SELECT id, report_count FROM threat_campaigns WHERE campaign_fingerprint = ?",
            (fingerprint,)
        )
        existing_campaign = await cur.fetchone()

        if existing_campaign:
            camp_id = existing_campaign["id"]
            new_count = existing_campaign["report_count"] + 1
            velocity = "RISING" if new_count >= 3 else "ACTIVE"

            await db.execute(
                """
                UPDATE threat_campaigns
                SET report_count = ?, velocity = ?, last_seen = CURRENT_TIMESTAMP,
                    risk_level = CASE WHEN ? = 'CRITICAL' THEN 'CRITICAL' ELSE risk_level END
                WHERE id = ?
                """,
                (new_count, velocity, risk, camp_id)
            )
        else:
            velocity = "NEW"
            cur_ins = await db.execute(
                """
                INSERT INTO threat_campaigns (campaign_fingerprint, canonical_name, threat_category, risk_level, report_count, velocity)
                VALUES (?, ?, ?, ?, 1, 'NEW')
                """,
                (fingerprint, canonical_name, category, risk)
            )
            camp_id = cur_ins.lastrowid

        # ── Step B: Insert Structured Threat Report (with audit trail) ──
        cursor = await db.execute(
            """
            INSERT INTO threat_reports (
                item_id, campaign_id, campaign_fingerprint, source_intent, risk_level,
                threat_category, threat_title, the_lure, the_hidden_trap,
                red_flags, action_checklist, extracted_entities,
                relevance_score, confidence_score, unmatched_reason,
                audit_status, audit_corrections
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item_id,
                camp_id,
                fingerprint,
                payload["source_intent"],
                payload["risk_level"],
                payload["threat_category"],
                payload["threat_title"],
                payload.get("the_lure"),
                payload.get("the_hidden_trap"),
                json.dumps(payload.get("red_flags", [])),
                json.dumps(payload.get("action_checklist", [])),
                json.dumps(payload.get("extracted_entities", [])),
                payload["relevance_score"],
                payload["confidence_score"],
                payload.get("unmatched_reason"),
                audit_status,
                json.dumps(audit_corrections or []),
            ),
        )
        await db.commit()
        report_id = cursor.lastrowid
        return report_id, camp_id, velocity


async def mark_notified(threat_report_id: int) -> None:
    """Mark a threat report as having been sent to Discord."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "UPDATE threat_reports SET notified = 1 WHERE id = ?",
            (threat_report_id,),
        )
        await db.commit()


async def log_telemetry(
    collector_id: str,
    source_name: str,
    target_url: str,
    status: str,
    error_message: str | None = None,
    items_found: int = 0,
    items_new: int = 0,
    heal_triggered: bool = False,
) -> None:
    """Log a scrape cycle event to the telemetry table."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            """
            INSERT INTO scraper_telemetry (
                collector_id, source_name, target_url, status,
                error_message, items_found, items_new, heal_triggered
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                collector_id,
                source_name,
                target_url,
                status,
                error_message,
                items_found,
                items_new,
                1 if heal_triggered else 0,
            ),
        )
        await db.commit()


async def get_scraped_items_by_ids(item_ids: list[int]) -> list[dict]:
    """Fetch scraped items by their IDs. Used by the pipeline after scraping."""
    if not item_ids:
        return []
    placeholders = ",".join("?" * len(item_ids))
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            f"SELECT id, source_url, raw_title, raw_content FROM scraped_items WHERE id IN ({placeholders})",
            item_ids,
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


# ──────────────────────────────────────────────────────────────
# Dashboard query helpers
# ──────────────────────────────────────────────────────────────

async def get_recent_threats(limit: int = 20) -> list[dict]:
    """Fetch the latest N threat reports with their source details."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT tr.*, si.source_name, si.source_url, si.scraped_at
            FROM threat_reports tr
            JOIN scraped_items si ON si.id = tr.item_id
            ORDER BY tr.analyzed_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_telemetry_log(limit: int = 50) -> list[dict]:
    """Fetch the latest N scraper telemetry entries."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM scraper_telemetry ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_active_campaigns(limit: int = 10) -> list[dict]:
    """Fetch active and rising threat campaigns ordered by velocity and report count."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT * FROM threat_campaigns
            ORDER BY
                CASE velocity
                    WHEN 'RISING' THEN 1
                    WHEN 'ACTIVE' THEN 2
                    WHEN 'NEW' THEN 3
                    ELSE 4
                END,
                report_count DESC,
                last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_dashboard_stats() -> dict:
    """Quick summary stats for the dashboard header."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        total_scraped = (await (await db.execute("SELECT COUNT(*) FROM scraped_items")).fetchone())[0]
        total_threats = (await (await db.execute("SELECT COUNT(*) FROM threat_reports")).fetchone())[0]
        active_campaigns = (await (await db.execute("SELECT COUNT(*) FROM threat_campaigns")).fetchone())[0]
        alerts_sent = (await (await db.execute("SELECT COUNT(*) FROM threat_reports WHERE notified = 1")).fetchone())[0]
        heals = (await (await db.execute("SELECT COUNT(*) FROM scraper_telemetry WHERE heal_triggered = 1")).fetchone())[0]
        return {
            "total_scraped": total_scraped,
            "total_threats": total_threats,
            "active_campaigns": active_campaigns,
            "alerts_sent": alerts_sent,
            "self_heals": heals,
        }
