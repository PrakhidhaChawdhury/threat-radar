"""
tests/test_campaign_clustering.py — Verifies Campaign Clustering, Velocity, & IOC extraction.
Uses an isolated in-memory or temporary test DB to protect production data.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Use an isolated test database
TEST_DB = "test_clustering.db"
os.environ["DATABASE_PATH"] = TEST_DB
import config
config.DATABASE_PATH = TEST_DB

import aiosqlite
from db.database import (
    init_db,
    save_scraped_item,
    save_threat_report,
    get_active_campaigns,
    get_dashboard_stats,
)


async def run_clustering_test():
    print("\n----------------------------------------------------------")
    print("  TESTING CAMPAIGN CLUSTERING & VELOCITY ENGINE")
    print("----------------------------------------------------------")

    # Clean previous test database if exists
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

    await init_db()

    # ── Test 1: First Threat Ingested (Creates a NEW Campaign) ─
    item_id_1 = await save_scraped_item(
        source_name="test_feed",
        source_url="https://example.com/report-1",
        raw_title="Recruiter sent malicious npm repo on Telegram",
        raw_content="The recruiter @tech_intern_dev asked to run npm install on github.com/fake/repo",
        status="PENDING",
    )

    payload_1 = {
        "campaign_fingerprint": "DEV_NPM_POSTINSTALL_STEALER",
        "threat_title": "Fake Internship Repo Executing Postinstall Payload",
        "threat_category": "Developer Tooling Compromise",
        "risk_level": "CRITICAL",
        "source_intent": "ACTIVE_LURE",
        "the_lure": "₹40k remote React internship take-home assignment",
        "the_hidden_trap": "Postinstall script steals discord tokens",
        "red_flags": ["Recruiter on telegram", "Postinstall script executes curl"],
        "action_checklist": ["Inspect package.json", "Run in container"],
        "extracted_entities": ["@tech_intern_dev", "github.com/fake/repo"],
        "relevance_score": 10,
        "confidence_score": 0.95,
    }

    rep_id_1, camp_id_1, velocity_1 = await save_threat_report(item_id_1, payload_1)
    print(f"[TEST 1] Report 1 created: ID={rep_id_1}, Campaign ID={camp_id_1}, Velocity={velocity_1}")
    assert velocity_1 == "NEW", f"Expected velocity 'NEW', got {velocity_1}"
    assert camp_id_1 == 1

    # ── Test 2: Second Threat (Same Fingerprint -> Clusters into Campaign) ─
    item_id_2 = await save_scraped_item(
        source_name="test_feed",
        source_url="https://example.com/report-2",
        raw_title="Another student targeted by fake take-home repo",
        raw_content="Targeted by @tech_intern_dev with fake React test repo",
        status="PENDING",
    )

    payload_2 = {
        "campaign_fingerprint": "DEV_NPM_POSTINSTALL_STEALER",
        "threat_title": "Second variant of React Take-Home Token Stealer",
        "threat_category": "Developer Tooling Compromise",
        "risk_level": "CRITICAL",
        "source_intent": "VICTIM_REPORT",
        "the_lure": "Remote developer take-home test",
        "the_hidden_trap": "Malicious postinstall lifecycle hook",
        "red_flags": ["Unverified recruiter", "Obfuscated code in install scripts"],
        "action_checklist": ["Run npm install with --ignore-scripts"],
        "extracted_entities": ["@tech_intern_dev"],
        "relevance_score": 10,
        "confidence_score": 0.92,
    }

    rep_id_2, camp_id_2, velocity_2 = await save_threat_report(item_id_2, payload_2)
    print(f"[TEST 2] Report 2 created: ID={rep_id_2}, Campaign ID={camp_id_2}, Velocity={velocity_2}")
    assert camp_id_2 == camp_id_1, "Expected Report 2 to cluster into Campaign 1!"
    assert velocity_2 == "ACTIVE", f"Expected velocity 'ACTIVE', got {velocity_2}"

    # ── Test 3: Third Threat (Triggers RISING Velocity Spike) ─
    item_id_3 = await save_scraped_item(
        source_name="test_feed",
        source_url="https://example.com/report-3",
        raw_title="Third report of malicious take-home repo",
        raw_content="Same npm token stealer repo reported by another applicant",
        status="PENDING",
    )

    payload_3 = {
        "campaign_fingerprint": "DEV_NPM_POSTINSTALL_STEALER",
        "threat_title": "Third variant of React Token Stealer",
        "threat_category": "Developer Tooling Compromise",
        "risk_level": "CRITICAL",
        "source_intent": "VICTIM_REPORT",
        "the_lure": "Remote internship opportunity",
        "the_hidden_trap": "Token stealer",
        "red_flags": ["Telegram recruiter"],
        "action_checklist": ["Block recruiter"],
        "extracted_entities": ["@tech_intern_dev"],
        "relevance_score": 10,
        "confidence_score": 0.90,
    }

    rep_id_3, camp_id_3, velocity_3 = await save_threat_report(item_id_3, payload_3)
    print(f"[TEST 3] Report 3 created: ID={rep_id_3}, Campaign ID={camp_id_3}, Velocity={velocity_3}")
    assert camp_id_3 == camp_id_1
    assert velocity_3 == "RISING", f"Expected velocity 'RISING', got {velocity_3}"

    # ── Test 4: Verify Stats & Campaign List ──────────────────
    stats = await get_dashboard_stats()
    campaigns = await get_active_campaigns()

    print(f"[TEST 4] Dashboard Stats: {stats}")
    print(f"[TEST 4] Active Campaigns List: {len(campaigns)}")
    assert stats["active_campaigns"] == 1
    assert stats["total_threats"] == 3
    assert campaigns[0]["report_count"] == 3
    assert campaigns[0]["velocity"] == "RISING"

    # Cleanup test DB
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

    print("\n----------------------------------------------------------")
    print("  [SUCCESS] ALL CAMPAIGN CLUSTERING & VELOCITY TESTS PASSED!")
    print("----------------------------------------------------------\n")


if __name__ == "__main__":
    asyncio.run(run_clustering_test())
