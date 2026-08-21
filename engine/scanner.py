"""
engine/scanner.py — Interactive Threat Scanner & Lure Interceptor.

Accepts any raw suspicious text (job offer email, Telegram DM, repository link,
Upwork contract, SMS lure) and evaluates it against:
1. Live Threat Radar Campaign Memory (from SQLite)
2. Developer / Student specific scam heuristics
3. Gemini 3.7 Flash analytical reasoning

Returns a clean, structured ScanVerdict with zero technical jargon.
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

import config
from db.database import get_active_campaigns


class ScanVerdict(BaseModel):
    verdict: str = Field(
        description="Must be exactly one of: 'CRITICAL_SCAM', 'SUSPICIOUS', 'LIKELY_SAFE'"
    )
    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in this evaluation (0.0 to 1.0)"
    )
    threat_category: str = Field(
        description="Short category name, e.g. 'Fake Recruiter / Malicious Assessment', 'Task & Deposit Fraud', 'UPI Phishing', 'Clean / Benign'"
    )
    plain_english_trap: str = Field(
        description="Explain what the attacker is trying to do to the victim in 1-2 simple, plain English sentences. No academic jargon."
    )
    red_flags_detected: List[str] = Field(
        description="2 to 4 specific manipulative hooks, phrases, or warning signs found in the input text."
    )
    immediate_safety_steps: List[str] = Field(
        description="2 to 3 concrete, immediate actions the user should take right now (e.g. 'Do not clone or run npm install', 'Block on Telegram')."
    )
    matched_campaign_fingerprint: Optional[str] = Field(
        default=None,
        description="Fingerprint of matching active campaign (e.g. 'DEV_NPM_POSTINSTALL_STEALER', 'CAREER_TELEGRAM_TASK_DEPOSIT') if recognized, else None."
    )


_SCANNER_SYSTEM_PROMPT = f"""You are Threat Radar's Lure Interceptor and Scam Diagnostic Engine.
Your job is to protect junior developers, students, and freelancers in India from being scammed, hacked, or robbed.

{config.USER_ZERO_PERSONA}

RULES:
1. Be direct, protective, and plain-spoken. Avoid abstract enterprise security buzzwords.
2. If someone is being asked to:
   - Run unknown repositories with postinstall scripts / test apps -> Flag as CRITICAL_SCAM (Developer Infostealer).
   - Deposit money for tasks, security fees, onboarding kits, or "registration" -> Flag as CRITICAL_SCAM (Task/Deposit Fraud).
   - Move from LinkedIn/Upwork to Telegram/WhatsApp for "immediate hiring" -> Flag as SUSPICIOUS or CRITICAL_SCAM.
   - Pay small delivery/re-attempt fees for couriers via unfamiliar links -> Flag as CRITICAL_SCAM (UPI Phishing).
3. If the input is a genuine, standard message with zero red flags -> Flag as LIKELY_SAFE.
"""


async def scan_suspicious_input(input_text: str) -> ScanVerdict:
    """
    Evaluates suspicious user input against active campaign memory + LLM reasoning.
    """
    # 1. Fetch current active campaign memory from local DB
    active_campaigns = await get_active_campaigns(limit=10)
    campaign_context = ""
    if active_campaigns:
        camp_lines = [
            f"- [{c['campaign_fingerprint']}] {c['canonical_name']} (Velocity: {c['velocity']}, Reports: {c['report_count']})"
            for c in active_campaigns
        ]
        campaign_context = "ACTIVE THREAT CAMPAIGNS CURRENTLY ON RADAR:\n" + "\n".join(camp_lines)

    user_prompt = f"""Evaluate this message / offer / link for potential threats:

=== INPUT TEXT TO SCAN ===
{input_text.strip()}
=== END INPUT TEXT ===

{campaign_context}

Analyze the input and produce a structured ScanVerdict."""

    client = genai.Client(api_key=config.GEMINI_API_KEY)

    response = client.models.generate_content(
        model=config.GEMINI_MODEL,
        contents=user_prompt,
        config=types.GenerateContentConfig(
            system_instruction=_SCANNER_SYSTEM_PROMPT,
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=ScanVerdict,
        ),
    )

    verdict = ScanVerdict.model_validate_json(response.text)
    return verdict
