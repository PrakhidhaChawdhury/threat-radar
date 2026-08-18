"""
main.py — Async pipeline orchestrator.

Usage:
  uv run python main.py          # Continuous polling loop (every POLLING_INTERVAL_MINUTES)
  uv run python main.py --once   # Single run and exit (great for demos and testing)
  uv run python main.py --serve  # Start the web dashboard only
"""

import asyncio
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import click
import uvicorn

import config
from db.database import (
    init_db,
    update_scraped_item_status,
    save_threat_report,
    mark_notified,
    get_scraped_items_by_ids,
)
from scrapers.runner import run_source
from engine.heuristics import run_heuristic_gate
from engine.evaluator import evaluate_threat
from engine.schemas import ThreatIntelligencePayload
from notifier.discord import send_threat_alert, should_alert


async def run_pipeline() -> dict:
    """
    Execute one full pipeline cycle across all configured sources.
    Returns a summary dict of what happened this cycle.
    """
    print("\n" + "═" * 60)
    print("  🛡️  THREAT RADAR — Pipeline Cycle Starting")
    print("═" * 60)

    summary = {
        "sources_processed": 0,
        "items_scraped": 0,
        "items_skipped_benign": 0,
        "threats_analyzed": 0,
        "alerts_sent": 0,
        "parse_failures": 0,
    }

    # ── Phase 1: Scraping ─────────────────────────────────────
    # Gather all new item IDs from all sources concurrently
    all_new_item_ids: list[int] = []

    for source in config.SCRAPER_SOURCES:
        new_ids = await run_source(source)
        all_new_item_ids.extend(new_ids)
        summary["sources_processed"] += 1

    summary["items_scraped"] = len(all_new_item_ids)

    if not all_new_item_ids:
        print("\n[PIPELINE] No new items this cycle. Everything is up to date.")
        return summary

    print(f"\n[PIPELINE] {len(all_new_item_ids)} new items to analyze.")

    # ── Phase 2: Fetch raw content for analysis ───────────────
    rows = await get_scraped_items_by_ids(all_new_item_ids)

    # ── Phase 3: Heuristic Gate → LLM → Save → Alert ─────────
    for row in rows:
        item_id = row["id"]
        source_url = row["source_url"]
        raw_title = row["raw_title"]
        raw_content = row["raw_content"]

        print(f"\n[PIPELINE] Processing item {item_id}: {(raw_title or source_url)[:70]}")

        # Step 1: Zero-cost heuristic gate
        heuristic = run_heuristic_gate(raw_title, raw_content)

        if not heuristic.passed:
            print(f"[PIPELINE]   ↳ SKIPPED: No threat signals found (heuristic gate).")
            await update_scraped_item_status(item_id, "SKIPPED_BENIGN")
            summary["items_skipped_benign"] += 1
            continue

        print(f"[PIPELINE]   ↳ Heuristic matched: {heuristic.matched_buckets}")

        # Step 2: Gemini structured analysis
        payload: ThreatIntelligencePayload | None = await evaluate_threat(
            raw_title=raw_title,
            raw_content=raw_content,
            source_url=source_url,
        )

        if payload is None:
            await update_scraped_item_status(item_id, "FAILED_PARSING")
            summary["parse_failures"] += 1
            continue

        # Step 3: Save to threat_reports and cluster into campaign
        report_id, camp_id, velocity = await save_threat_report(item_id, payload.model_dump())
        await update_scraped_item_status(item_id, "ANALYZED")
        summary["threats_analyzed"] += 1
        print(f"[PIPELINE]   ↳ Clustered into Campaign #{camp_id} [{payload.campaign_fingerprint}] (Velocity: {velocity})")

        # Step 4: Conditional alert delivery
        if should_alert(payload):
            sent = await send_threat_alert(payload, source_url)
            if sent:
                await mark_notified(report_id)
                summary["alerts_sent"] += 1
        else:
            print(
                f"[PIPELINE]   ↳ Stored silently "
                f"(Relevance={payload.relevance_score}/10, Risk={payload.risk_level})"
            )

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "─" * 60)
    print(f"  ✅ Cycle complete:")
    print(f"     • Items scraped:       {summary['items_scraped']}")
    print(f"     • Skipped (benign):    {summary['items_skipped_benign']}")
    print(f"     • Threats analyzed:    {summary['threats_analyzed']}")
    print(f"     • Alerts sent:         {summary['alerts_sent']}")
    print(f"     • Parse failures:      {summary['parse_failures']}")
    print("─" * 60)

    return summary


async def polling_loop():
    """Continuous polling loop. Runs run_pipeline() every POLLING_INTERVAL_MINUTES."""
    interval_s = config.POLLING_INTERVAL_MINUTES * 60
    print(f"[MAIN] Starting polling loop. Interval: {config.POLLING_INTERVAL_MINUTES} minutes.")

    while True:
        await run_pipeline()
        print(f"\n[MAIN] Sleeping for {config.POLLING_INTERVAL_MINUTES} minutes...")
        await asyncio.sleep(interval_s)


# ──────────────────────────────────────────────────────────────
# CLI Entry Points
# ──────────────────────────────────────────────────────────────

@click.group()
def cli():
    """🛡️  Threat Radar — Personalized Cybersecurity Intelligence Pipeline"""
    pass


@cli.command()
def run():
    """Start the continuous polling pipeline loop."""
    asyncio.run(_startup_and(polling_loop))


@cli.command()
def once():
    """Run a single pipeline cycle and exit. Good for testing and demos."""
    asyncio.run(_startup_and(run_pipeline))


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to serve on")
def serve(host: str, port: int):
    """Start the web dashboard server only (no scraping)."""
    asyncio.run(init_db())
    print(f"[MAIN] Starting dashboard at http://localhost:{port} (bound to {host}:{port})")
    uvicorn.run("web.app:app", host=host, port=port, reload=False)


@cli.command()
def pipeline_and_serve():
    """Start both the pipeline and the web dashboard concurrently."""
    async def _run_both():
        await init_db()
        pipeline_task = asyncio.create_task(polling_loop())
        # Run dashboard in a thread (uvicorn is not async-native)
        loop = asyncio.get_event_loop()
        server_config = uvicorn.Config("web.app:app", host="127.0.0.1", port=8000)
        server = uvicorn.Server(server_config)
        server_task = asyncio.create_task(server.serve())
        await asyncio.gather(pipeline_task, server_task)

    asyncio.run(_run_both())


async def _startup_and(fn):
    """Initialize DB then run fn."""
    await init_db()
    await fn()


if __name__ == "__main__":
    cli()
