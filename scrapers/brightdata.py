"""
scrapers/brightdata.py — Bright Data REST API client + self-healing subprocess hooks.

REST API (httpx.AsyncClient) for:
  - trigger_collector()  → POST /dca/trigger
  - poll_result()        → GET  /dca/get_result (with exponential backoff)

Subprocess (only when anomaly healing is needed) for:
  - heal_collector()     → bdata scraper heal
  - approve_collector()  → bdata scraper approve
  - reject_collector()   → bdata scraper approve --reject
"""

import asyncio
import subprocess
import time
from typing import Any, Optional

import httpx

import config


_HEADERS = {
    "Authorization": f"Bearer {config.BRIGHTDATA_API_KEY}",
    "Content-Type": "application/json",
}

# How long to wait between polling attempts (seconds) and max total wait
_POLL_INTERVAL_S = 3
_POLL_TIMEOUT_S = 30
_MAX_ATTEMPTS = 10


async def trigger_collector(collector_id: str, url: str) -> Optional[str]:
    """
    Trigger a Bright Data collector via REST API.
    Returns the response_id / snapshot_id to use for polling, or None on failure.
    """
    if not collector_id:
        print(f"[BRIGHTDATA] ⚠️  No Collector ID set. Skipping trigger for: {url}")
        return None

    endpoint = f"{config.BRIGHTDATA_API_BASE}/dca/trigger?collector={collector_id}&queue_next=1"
    payload = [{"url": url}]

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(endpoint, headers=_HEADERS, json=payload)
            resp.raise_for_status()
            data = resp.json()
            snapshot_id = data.get("response_id") or data.get("collection_id") or data.get("snapshot_id")
            print(f"[BRIGHTDATA] Triggered collector {collector_id} → snapshot: {snapshot_id}")
            return snapshot_id
    except httpx.HTTPStatusError as e:
        print(f"[BRIGHTDATA] HTTP error triggering collector {collector_id}: {e.response.status_code} {e.response.text}")
        return None
    except Exception as e:
        print(f"[BRIGHTDATA] Error triggering collector {collector_id}: {e}")
        return None


async def poll_result(snapshot_id: str) -> Optional[list[dict]]:
    """
    Poll for collection results (capped at max ~30 seconds).
    Tries DCA get_result and dataset endpoints.
    """
    start = time.monotonic()
    attempt = 0

    async with httpx.AsyncClient(timeout=15.0) as client:
        while attempt < _MAX_ATTEMPTS:
            elapsed = time.monotonic() - start
            if elapsed > _POLL_TIMEOUT_S:
                print(f"[BRIGHTDATA] ⏱️ Polling timed out ({_POLL_TIMEOUT_S}s) for snapshot {snapshot_id}. Falling back.")
                return None

            try:
                # 1. Try DCA get_result
                endpoint = f"{config.BRIGHTDATA_API_BASE}/dca/get_result?response_id={snapshot_id}&format=json"
                resp = await client.get(endpoint, headers=_HEADERS)

                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and data:
                        print(f"[BRIGHTDATA] ✓ Got result for snapshot {snapshot_id}: {len(data)} items")
                        return data
                    elif isinstance(data, dict):
                        items = data.get("data") or data.get("items")
                        if items and isinstance(items, list):
                            print(f"[BRIGHTDATA] ✓ Got result for snapshot {snapshot_id}: {len(items)} items")
                            return items

                # 2. Try DCA dataset
                ds_endpoint = f"{config.BRIGHTDATA_API_BASE}/dca/dataset?id={snapshot_id}"
                ds_resp = await client.get(ds_endpoint, headers=_HEADERS)

                if ds_resp.status_code == 200:
                    ds_data = ds_resp.json()
                    if isinstance(ds_data, list) and ds_data:
                        print(f"[BRIGHTDATA] ✓ Got dataset result for {snapshot_id}: {len(ds_data)} items")
                        return ds_data
                    elif isinstance(ds_data, dict):
                        if ds_data.get("status") not in ("collecting", "running", "building"):
                            items = ds_data.get("data") or ds_data.get("items") or [ds_data]
                            if items:
                                return items

                attempt += 1
                wait = min(2 + attempt, 4)
                print(f"[BRIGHTDATA] Processing ({attempt}/{_MAX_ATTEMPTS})... waiting {wait}s")
                await asyncio.sleep(wait)

            except Exception as e:
                attempt += 1
                print(f"[BRIGHTDATA] Polling attempt error: {e}")
                await asyncio.sleep(2)

    print(f"[BRIGHTDATA] ⏱️ Maximum poll attempts reached ({_MAX_ATTEMPTS}) for snapshot {snapshot_id}.")
    return None


async def scrape_url(collector_id: str, url: str) -> Optional[list[dict]]:
    """
    Scrapes a target URL.
    Attempts Bright Data collector first. If collector is pending/slow,
    falls back cleanly to direct public threat endpoints so the pipeline never hangs.
    """
    if collector_id:
        snapshot_id = await trigger_collector(collector_id, url)
        if snapshot_id:
            result = await poll_result(snapshot_id)
            if result:
                return result

    # ── Clean Ingestion Fallback ────────────────────────────────
    print(f"[RUNNER] ⚡ Using live feed direct fallback for: {url}")
    try:
        custom_headers = {
            "User-Agent": "ThreatRadar-Intelligence-Bot/1.0 (Cybersecurity Analysis)",
            "Accept": "application/json, text/html",
        }
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            # If GitHub advisories
            if "github.com" in url:
                api_url = "https://api.github.com/advisories?per_page=20&sort=updated"
                resp = await client.get(api_url, headers=custom_headers)
                if resp.status_code == 200:
                    raw_advisories = resp.json()
                    parsed_items = []
                    for adv in raw_advisories:
                        vulns = adv.get("vulnerabilities") or []
                        pkg_info = vulns[0].get("package", {}) if vulns else {}
                        parsed_items.append({
                            "url": adv.get("html_url"),
                            "title": adv.get("summary") or adv.get("cve_id") or "Security Advisory",
                            "content": adv.get("description") or adv.get("summary"),
                            "severity": adv.get("severity"),
                            "cve_identifier": adv.get("cve_id"),
                            "package_name": pkg_info.get("name"),
                            "ecosystem": pkg_info.get("ecosystem"),
                        })
                    print(f"[RUNNER] ✓ Fallback fetched {len(parsed_items)} live GitHub security advisories")
                    return parsed_items

            # If Reddit r/Scams
            if "reddit.com" in url:
                reddit_json_url = "https://www.reddit.com/r/Scams/new.json?limit=20"
                resp = await client.get(reddit_json_url, headers=custom_headers)
                if resp.status_code == 200:
                    raw_data = resp.json()
                    children = raw_data.get("data", {}).get("children", [])
                    parsed_items = []
                    for post in children:
                        pdata = post.get("data", {})
                        parsed_items.append({
                            "url": f"https://www.reddit.com{pdata.get('permalink')}",
                            "title": pdata.get("title"),
                            "content": pdata.get("selftext") or pdata.get("title"),
                            "author": pdata.get("author"),
                        })
                    print(f"[RUNNER] ✓ Fallback fetched {len(parsed_items)} live Reddit scam posts")
                    return parsed_items

            # If HackerNews Developer Threats (hnrss.org / ycombinator.com)
            if "hnrss.org" in url or "ycombinator.com" in url:
                import xml.etree.ElementTree as ET
                import re

                resp = await client.get(url, headers=custom_headers)
                if resp.status_code == 200:
                    try:
                        root = ET.fromstring(resp.text)
                        parsed_items = []
                        for item in root.findall(".//item"):
                            title = item.findtext("title")
                            link = item.findtext("link") or item.findtext("comments")
                            raw_desc = item.findtext("description") or title or ""
                            clean_desc = re.sub(r"<[^>]+>", " ", raw_desc).strip()
                            if title and link:
                                parsed_items.append({
                                    "url": link,
                                    "title": title,
                                    "content": clean_desc if len(clean_desc) > 20 else title,
                                })
                        if parsed_items:
                            print(f"[RUNNER] ✓ Fallback parsed {len(parsed_items)} live HackerNews threat stories")
                            return parsed_items
                    except Exception as parse_err:
                        print(f"[RUNNER] HN RSS parse error: {parse_err}")

    except Exception as e:
        print(f"[RUNNER] Fallback fetch error: {e}")

    return None


# ──────────────────────────────────────────────────────────────
# Self-Healing Subprocess Hooks
# The CLI is ONLY used for heal/approve — not for normal scraping.
# ──────────────────────────────────────────────────────────────

def heal_collector(collector_id: str, description: str) -> bool:
    """
    Trigger `bdata scraper heal <COLLECTOR_ID> "<description>"`.
    Returns True if the heal command exited successfully.
    This is a blocking subprocess call — intended to be run in an executor.
    """
    print(f"[BRIGHTDATA] 🔧 Triggering self-heal for {collector_id}: '{description}'")
    try:
        result = subprocess.run(
            ["npx", "-y", "@brightdata/cli", "scraper", "heal", collector_id, description],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            print(f"[BRIGHTDATA] ✓ Heal proposed for {collector_id}")
            print(result.stdout)
            return True
        else:
            print(f"[BRIGHTDATA] ✗ Heal failed for {collector_id}: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[BRIGHTDATA] Heal subprocess timed out for {collector_id}")
        return False
    except Exception as e:
        print(f"[BRIGHTDATA] Heal subprocess error: {e}")
        return False


def approve_collector(collector_id: str) -> bool:
    """
    Approve the pending heal fix: `bdata scraper approve <COLLECTOR_ID>`.
    Returns True on success.
    """
    print(f"[BRIGHTDATA] ✅ Approving heal for {collector_id}")
    try:
        result = subprocess.run(
            ["npx", "-y", "@brightdata/cli", "scraper", "approve", collector_id],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print(f"[BRIGHTDATA] ✓ Heal approved for {collector_id}")
            return True
        else:
            print(f"[BRIGHTDATA] ✗ Approve failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"[BRIGHTDATA] Approve subprocess error: {e}")
        return False


def reject_collector(collector_id: str) -> bool:
    """
    Reject the pending heal fix: `bdata scraper approve <COLLECTOR_ID> --reject`.
    Use when the sanity check shows the proposed fix grabs sidebar content.
    """
    print(f"[BRIGHTDATA] ❌ Rejecting proposed heal for {collector_id}")
    try:
        result = subprocess.run(
            ["npx", "-y", "@brightdata/cli", "scraper", "approve", collector_id, "--reject"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[BRIGHTDATA] Reject subprocess error: {e}")
        return False
