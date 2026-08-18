"""
scrapers/runner.py — Discovery → SQLite Dedup Gate → Detail Scraper → Sanity Guard.

This is the core scraping orchestration layer. For each configured source:
  1. Fetch the discovery page (list of item URLs) via Bright Data.
  2. Filter against SQLite URL hash gate (skip already-seen URLs).
  3. Fetch detail pages for NEW URLs only.
  4. Run sanity assertions on extracted content.
  5. If sanity fails → trigger self-healing loop.
  6. Save clean items to SQLite for downstream LLM processing.
"""

import asyncio
import json
from typing import Optional

import config
from db.database import (
    is_url_seen,
    save_scraped_item,
    update_scraped_item_status,
    log_telemetry,
)
from scrapers.brightdata import (
    scrape_url,
    heal_collector,
    approve_collector,
    reject_collector,
)


def _passes_sanity_check(content: str | None) -> tuple[bool, str]:
    """
    Validates extracted content is real post body (not sidebar/ad/null).
    Returns (passed: bool, reason: str).
    """
    if not content:
        return False, "Content is None or empty"

    stripped = content.strip()

    if len(stripped) < config.SANITY_CONTENT_MIN_CHARS:
        return False, f"Content too short ({len(stripped)} chars < {config.SANITY_CONTENT_MIN_CHARS})"

    if len(stripped) > config.SANITY_CONTENT_MAX_CHARS:
        return False, f"Content too long ({len(stripped)} chars > {config.SANITY_CONTENT_MAX_CHARS}) — likely a dump page"

    # Basic signal check: real posts have minimal word variety
    words = stripped.split()
    if len(words) < 5:
        return False, f"Content too sparse ({len(words)} words)"

    return True, "OK"


def _extract_item_fields(raw_item: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Normalize field names from Bright Data's JSON output.
    Different collectors may return slightly different key names.
    Returns (url, title, content).
    """
    url = (
        raw_item.get("url")
        or raw_item.get("link")
        or raw_item.get("permalink")
        or raw_item.get("html_url")
        or raw_item.get("advisory_url")
        or raw_item.get("href")
        or raw_item.get("post_url")
    )
    if url:
        if url.startswith("/r/") or "reddit.com" in url or "r/Scams" in url:
            if url.startswith("/"):
                url = f"https://www.reddit.com{url}"
        elif url.startswith("/"):
            url = f"https://github.com{url}"
        elif "api.github.com/advisories/" in url:
            url = url.replace("api.github.com/advisories/", "github.com/advisories/")

    title = (
        raw_item.get("title")
        or raw_item.get("advisory_title")
        or raw_item.get("name")
        or raw_item.get("summary")
        or raw_item.get("subject")
        or raw_item.get("post_title")
    )
    content = (
        raw_item.get("content")
        or raw_item.get("body")
        or raw_item.get("selftext")       # Reddit posts
        or raw_item.get("post_text")
        or raw_item.get("description")
        or raw_item.get("description_summary")
        or raw_item.get("details")
    )

    extras = []
    if raw_item.get("package_name"):
        extras.append(f"Package: {raw_item.get('package_name')}")
    if raw_item.get("ecosystem"):
        extras.append(f"Ecosystem: {raw_item.get('ecosystem')}")
    if raw_item.get("severity") or raw_item.get("severity_level"):
        extras.append(f"Severity: {raw_item.get('severity') or raw_item.get('severity_level')}")
    if raw_item.get("cve_identifier") or raw_item.get("cve"):
        extras.append(f"CVE: {raw_item.get('cve_identifier') or raw_item.get('cve')}")

    # Regex extraction of embedded handles & links (IOCs)
    if content:
        import re
        handles = re.findall(r"@[\w_]{4,32}", content)
        if handles:
            extras.append(f"Extracted Handles: {', '.join(set(handles[:3]))}")

    if extras:
        extra_text = " | ".join(extras)
        if content:
            content = f"{extra_text}\n\n{content}"
        else:
            content = extra_text

    return url, title, content


async def _run_self_heal_loop(
    collector_id: str,
    source_name: str,
    target_url: str,
    failure_reason: str,
) -> bool:
    """
    When sanity check fails, attempt one round of self-healing.
    Returns True if the heal was successfully applied.
    """
    print(f"[RUNNER] ⚡ Initiating self-heal for {source_name}: {failure_reason}")

    # Run heal in a thread (blocking subprocess)
    loop = asyncio.get_event_loop()
    heal_ok = await loop.run_in_executor(
        None, heal_collector, collector_id, failure_reason
    )

    if not heal_ok:
        await log_telemetry(
            collector_id=collector_id,
            source_name=source_name,
            target_url=target_url,
            status="FAILED",
            error_message=f"Heal subprocess failed: {failure_reason}",
            heal_triggered=True,
        )
        return False

    # Re-run the scraper to verify the healed output
    print(f"[RUNNER] Re-running scraper after heal to validate...")
    result = await scrape_url(collector_id, target_url)

    if not result:
        await loop.run_in_executor(None, reject_collector, collector_id)
        await log_telemetry(
            collector_id=collector_id,
            source_name=source_name,
            target_url=target_url,
            status="FAILED",
            error_message="Healed scraper returned no results",
            heal_triggered=True,
        )
        return False

    # Check sanity on the healed output
    _, _, healed_content = _extract_item_fields(result[0] if result else {})
    sanity_ok, sanity_reason = _passes_sanity_check(healed_content)

    if not sanity_ok:
        print(f"[RUNNER] ❌ Healed output still fails sanity: {sanity_reason}. Rejecting.")
        await loop.run_in_executor(None, reject_collector, collector_id)
        await log_telemetry(
            collector_id=collector_id,
            source_name=source_name,
            target_url=target_url,
            status="FAILED",
            error_message=f"Post-heal sanity failed: {sanity_reason}",
            heal_triggered=True,
        )
        return False

    # Sanity passed — approve the fix permanently
    print(f"[RUNNER] ✅ Post-heal sanity passed. Approving fix.")
    await loop.run_in_executor(None, approve_collector, collector_id)
    await log_telemetry(
        collector_id=collector_id,
        source_name=source_name,
        target_url=target_url,
        status="HEALED",
        heal_triggered=True,
    )
    return True


async def run_source(source: dict) -> list[int]:
    """
    Run the full Discovery → Dedup → Detail → Sanity → Save pipeline
    for a single source definition.

    Returns list of saved scraped_item IDs (to be processed by the engine).
    """
    source_name: str = source["name"]
    label: str = source["label"]
    discovery_url: str = source["discovery_url"]
    collector_id: str = source["collector_id"]

    print(f"\n[RUNNER] ═══ Processing source: {label} ═══")

    if not collector_id:
        print(f"[RUNNER] ⚠️  No Collector ID for {label}. Add it to .env to enable this source.")
        return []

    # ── Step 1: Discovery Scrape ──────────────────────────────
    print(f"[RUNNER] Fetching discovery page: {discovery_url}")
    discovery_items = await scrape_url(collector_id, discovery_url)

    if not discovery_items:
        await log_telemetry(
            collector_id=collector_id,
            source_name=source_name,
            target_url=discovery_url,
            status="DEGRADED",
            error_message="Discovery scrape returned no items",
        )
        print(f"[RUNNER] ✗ Discovery returned no items for {label}")
        return []

    print(f"[RUNNER] Discovery returned {len(discovery_items)} items")

    # ── Step 2: SQLite URL Hash Dedup Gate ───────────────────
    new_items = []
    for item in discovery_items:
        url, title, _ = _extract_item_fields(item)
        if not url:
            continue
        if await is_url_seen(url):
            continue  # Already in DB — skip (0 credits spent)
        new_items.append(item)

    skipped = len(discovery_items) - len(new_items)
    print(f"[RUNNER] Dedup gate: {skipped} already seen, {len(new_items)} new items to process")

    if not new_items:
        await log_telemetry(
            collector_id=collector_id,
            source_name=source_name,
            target_url=discovery_url,
            status="HEALTHY",
            items_found=len(discovery_items),
            items_new=0,
        )
        return []

    # ── Step 3: Detail Scrape for New URLs (Capped at 10 items max per cycle) ──
    MAX_ITEMS_PER_CYCLE = 10
    items_to_process = new_items[:MAX_ITEMS_PER_CYCLE]
    if len(new_items) > MAX_ITEMS_PER_CYCLE:
        print(f"[RUNNER] ⚠️ Capping processing to {MAX_ITEMS_PER_CYCLE} items this cycle to conserve rate limits.")

    saved_item_ids: list[int] = []

    for raw_item in items_to_process:
        url, title, content = _extract_item_fields(raw_item)
        if not url:
            continue

        print(f"[RUNNER] Fetching detail: {url[:80]}...")

        # If discovery already returned full content (e.g. Reddit JSON API),
        # skip a redundant detail scrape and use what we have
        sanity_ok, sanity_reason = _passes_sanity_check(content)

        if not sanity_ok:
            # Need to fetch the detail page
            detail_result = await scrape_url(collector_id, url)

            if detail_result:
                _, detail_title, detail_content = _extract_item_fields(detail_result[0])
                title = detail_title or title
                content = detail_content

            # Re-check sanity after detail fetch
            sanity_ok, sanity_reason = _passes_sanity_check(content)

            if not sanity_ok:
                # Trigger self-healing loop
                healed = await _run_self_heal_loop(
                    collector_id=collector_id,
                    source_name=source_name,
                    target_url=url,
                    failure_reason=f"Detail content failed sanity check: {sanity_reason}",
                )
                if not healed:
                    # Log the URL as seen anyway to avoid re-attempting this broken item forever
                    try:
                        item_id = await save_scraped_item(
                            source_name=source_name,
                            source_url=url,
                            raw_title=title,
                            raw_content=content,
                            status="FAILED_PARSING",
                        )
                    except Exception:
                        pass
                    continue

        # ── Step 4: Save to SQLite ──────────────────────────
        try:
            item_id = await save_scraped_item(
                source_name=source_name,
                source_url=url,
                raw_title=title,
                raw_content=content,
                status="PENDING",
            )
            saved_item_ids.append(item_id)
            print(f"[RUNNER] ✓ Saved item ID={item_id}: {title[:60] if title else 'No title'}")
        except Exception as e:
            # IntegrityError from a race condition — item was saved between our check and insert
            print(f"[RUNNER] Skipping duplicate (race condition): {url[:60]} — {e}")

    await log_telemetry(
        collector_id=collector_id,
        source_name=source_name,
        target_url=discovery_url,
        status="HEALTHY",
        items_found=len(discovery_items),
        items_new=len(saved_item_ids),
    )

    print(f"[RUNNER] ✓ {label}: {len(saved_item_ids)} new items saved for analysis")
    return saved_item_ids
