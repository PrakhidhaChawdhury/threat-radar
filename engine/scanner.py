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


def _offline_heuristic_scan(input_text: str, active_campaigns: list) -> ScanVerdict:
    """
    Offline heuristic analyzer for when internet or Gemini API is unreachable.
    Evaluates pattern matches against common student/developer attack vectors.
    """
    text_lower = input_text.lower()
    
    # 1. Developer Take-Home / Infostealer / Malicious Repo
    if any(k in text_lower for k in ["npm install", "clone our", "github.com/", "test app", "benchmark", "take-home", "discord-token-grabber", "postinstall"]):
        matched_camp = "DEV_NPM_POSTINSTALL_STEALER" if any(c.get("campaign_fingerprint") == "DEV_NPM_POSTINSTALL_STEALER" for c in active_campaigns) else None
        return ScanVerdict(
            verdict="CRITICAL_SCAM",
            confidence_score=0.92,
            threat_category="Fake Recruiter / Malicious Repository",
            plain_english_trap="The recruiter is asking you to clone an unvetted repository that contains a malicious postinstall script or credential stealer designed to exfiltrate your browser cookies, Discord tokens, and crypto keys.",
            red_flags_detected=[
                "Unsolicited job or freelance offer with immediate pay promise",
                "Instruction to run 'npm install' or execute an unknown repository locally",
                "Lack of legitimate technical interview before assignment",
            ],
            immediate_safety_steps=[
                "DO NOT clone or run npm install / pip install on this repository",
                "Never run untrusted client code on your personal development machine",
                "Block the sender and report the GitHub account",
            ],
            matched_campaign_fingerprint=matched_camp or "DEV_NPM_POSTINSTALL_STEALER",
        )

    # 2. Task & Deposit / Telegram Job Fraud
    if any(k in text_lower for k in ["telegram", "security deposit", "task", "rate google maps", "₹", "daily commission", "earn ₹", "registration fee", "upi id"]):
        matched_camp = "CAREER_TELEGRAM_TASK_DEPOSIT" if any(c.get("campaign_fingerprint") == "CAREER_TELEGRAM_TASK_DEPOSIT" for c in active_campaigns) else None
        return ScanVerdict(
            verdict="CRITICAL_SCAM",
            confidence_score=0.95,
            threat_category="Task & Deposit Fraud",
            plain_english_trap="The scammer lures you with high daily earnings for trivial online tasks, but requires an upfront 'security deposit' or fee which will never be refunded.",
            red_flags_detected=[
                "Demands upfront security deposit or registration fee to start working",
                "Promises unrealistically high earnings for simple tasks (Google Maps reviews, YouTube likes)",
                "Directs communication away from legitimate platforms to Telegram/WhatsApp",
            ],
            immediate_safety_steps=[
                "Never send money or pay a 'deposit' to get a job or freelance gig",
                "Do not share your UPI ID or phone number",
                "Block and report the contact immediately on Telegram",
            ],
            matched_campaign_fingerprint=matched_camp or "CAREER_TELEGRAM_TASK_DEPOSIT",
        )

    # 3. Courier Phishing / Redelivery Fee
    if any(k in text_lower for k in ["dtdc", "indiapost", "delivery fee", "redeliver", "package", "reschedule", "incomplete address"]):
        return ScanVerdict(
            verdict="CRITICAL_SCAM",
            confidence_score=0.90,
            threat_category="Courier & Delivery Phishing",
            plain_english_trap="Fraudulent SMS pretending to be a courier service asking for a nominal redelivery fee via a fake payment gateway to steal your card or UPI credentials.",
            red_flags_detected=[
                "Unsolicited delivery notification with urgent 24-hour expiration",
                "Payment link on suspicious or shortened domain",
                "Request for payment to resolve an alleged address issue",
            ],
            immediate_safety_steps=[
                "Do not click the link or enter any payment/UPI details",
                "Check package tracking only on the courier's official app or website",
                "Delete and block the sender number",
            ],
            matched_campaign_fingerprint="COURIER_REDELIVERY_UPI_PHISH",
        )

    # 4. General Suspicious keywords
    if any(k in text_lower for k in ["otp", "suspended", "urgent", "account blocked", "kyc", "pan card", "verify now", "click here to unlock"]):
        return ScanVerdict(
            verdict="SUSPICIOUS",
            confidence_score=0.78,
            threat_category="Urgency & Credential Phishing",
            plain_english_trap="Message relies on artificial urgency or fear of account suspension to trick you into clicking a malicious link or revealing sensitive authentication details.",
            red_flags_detected=[
                "Urgent deadline threatening account deactivation",
                "Direct request to verify identity or enter credentials via external link",
            ],
            immediate_safety_steps=[
                "Do not share OTPs, passwords, or personal identification",
                "Verify account status directly through the official service provider",
            ],
            matched_campaign_fingerprint=None,
        )

    # Default: Likely Safe
    return ScanVerdict(
        verdict="LIKELY_SAFE",
        confidence_score=0.85,
        threat_category="Clean / Benign",
        plain_english_trap="No obvious phishing lures, malicious commands, or deposit fraud markers were detected in this text.",
        red_flags_detected=[],
        immediate_safety_steps=[
            "Always remain cautious before executing unknown scripts or sharing credentials",
        ],
        matched_campaign_fingerprint=None,
    )


async def scan_suspicious_input(input_text: str) -> ScanVerdict:
    """
    Evaluates suspicious user input against active campaign memory + LLM reasoning.
    Falls back cleanly to local heuristic analyzer if offline or Gemini API is unavailable.
    """
    # 1. Fetch current active campaign memory from local DB
    active_campaigns = await get_active_campaigns(limit=10)

    # 2. Try Gemini analysis if API key is present
    if config.GEMINI_API_KEY:
        try:
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
        except Exception as e:
            print(f"[SCANNER] Gemini call failed ({e}). Falling back to offline heuristic engine.")

    # 3. Offline Heuristic Fallback
    return _offline_heuristic_scan(input_text, active_campaigns)
