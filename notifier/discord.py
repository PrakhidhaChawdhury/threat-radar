"""
notifier/discord.py — Rich Discord embed alerts for high-signal threats.

Only fires when:
  - relevance_score >= RELEVANCE_THRESHOLD (default: 8)
  - risk_level in RISK_LEVELS_TO_ALERT (default: CRITICAL, HIGH)

Each embed includes: threat title, category, lure, trap, red flags, action checklist.
Color-coded by risk level. Silent on everything else.
"""

import json
import httpx

import config
from engine.schemas import ThreatIntelligencePayload


# Embed color codes by risk level
_COLORS = {
    "CRITICAL": 0xE74C3C,   # Red
    "HIGH": 0xE67E22,        # Orange
    "MEDIUM": 0xF1C40F,      # Yellow (not used for alerts, but defined for completeness)
    "LOW": 0x95A5A6,
    "BENIGN": 0x2ECC71,
}

_RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "BENIGN": "⚪",
}

_CATEGORY_EMOJI = {
    "Fake Internship / Job Scam": "💼",
    "Developer Tooling Compromise": "⚙️",
    "UPI / Financial Phishing": "💳",
    "Task & Deposit Scam": "📱",
    "Fake Courier / Delivery Fee": "📦",
    "Malicious GitHub Repository": "🐙",
    "Credential Phishing": "🔑",
    "Social Engineering / Impersonation": "🎭",
}


def _build_embed(payload: ThreatIntelligencePayload, source_url: str) -> dict:
    """Build a rich Discord embed dict from a ThreatIntelligencePayload."""

    risk_emoji = _RISK_EMOJI.get(payload.risk_level, "⚠️")
    color = _COLORS.get(payload.risk_level, 0xE74C3C)

    # Format red flags as bullet list
    red_flags_text = "\n".join(f"• {flag}" for flag in payload.red_flags)

    # Format action checklist as numbered steps
    checklist_text = "\n".join(
        f"**{i+1}.** {step}" for i, step in enumerate(payload.action_checklist)
    )

    fields = [
        {
            "name": "🎯 The Lure",
            "value": payload.the_lure or "_Not specified_",
            "inline": False,
        },
        {
            "name": "⚠️ The Hidden Trap",
            "value": payload.the_hidden_trap or "_Not specified_",
            "inline": False,
        },
        {
            "name": "🚩 Red Flags",
            "value": red_flags_text or "_None identified_",
            "inline": False,
        },
        {
            "name": "✅ What To Do Right Now",
            "value": checklist_text or "_No actions specified_",
            "inline": False,
        },
        {
            "name": "📊 Relevance Score",
            "value": f"`{payload.relevance_score}/10` for your profile",
            "inline": True,
        },
        {
            "name": "🔍 Source Intent",
            "value": f"`{payload.source_intent}`",
            "inline": True,
        },
        {
            "name": "🔗 Source",
            "value": f"[View Original Post]({source_url})",
            "inline": False,
        },
    ]

    return {
        "title": f"{risk_emoji} {payload.threat_title}",
        "description": f"**Category:** `{payload.threat_category}`",
        "color": color,
        "fields": fields,
        "footer": {
            "text": f"Threat Radar • Risk: {payload.risk_level} • Confidence: {payload.confidence_score:.0%}"
        },
    }


async def send_threat_alert(
    payload: ThreatIntelligencePayload,
    source_url: str,
) -> bool:
    """
    Send a high-signal threat alert to Discord.
    Returns True if the webhook call succeeded.

    Caller is responsible for checking relevance/risk thresholds before calling this.
    """
    if not config.DISCORD_WEBHOOK_URL:
        print("[DISCORD] ⚠️  No DISCORD_WEBHOOK_URL set. Skipping alert.")
        return False

    embed = _build_embed(payload, source_url)
    body = {
        "username": "Threat Radar",
        "avatar_url": "https://i.imgur.com/4M34hi2.png",
        "embeds": [embed],
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(config.DISCORD_WEBHOOK_URL, json=body)
            if resp.status_code in (200, 204):
                print(f"[DISCORD] ✅ Alert sent: '{payload.threat_title}'")
                return True
            else:
                print(f"[DISCORD] ✗ Webhook failed: {resp.status_code} {resp.text}")
                return False
    except Exception as e:
        print(f"[DISCORD] Error sending alert: {e}")
        return False


def should_alert(payload: ThreatIntelligencePayload) -> bool:
    """
    Gating logic: only alert if both thresholds are met.
    Centralized here so it's easy to adjust without hunting through code.
    """
    return (
        payload.relevance_score >= config.RELEVANCE_THRESHOLD
        and payload.risk_level in config.RISK_LEVELS_TO_ALERT
    )
