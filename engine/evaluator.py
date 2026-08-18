"""
engine/evaluator.py — Gemini 3.7 Flash threat intelligence evaluator.

Fallback chain:
  1. Structured Gemini call → Pydantic validation → return payload.
  2. ValidationError → 1 automatic retry with temperature=0.0.
  3. Double failure → return None, caller logs status="FAILED_PARSING".
  4. confidence_score < CONFIDENCE_FLOOR → downgrade risk to LOW, intent to UNKNOWN_DISCUSSION.
"""

import json
from typing import Optional

from google import genai
from google.genai import types
from pydantic import ValidationError

import config
from engine.schemas import ThreatIntelligencePayload


# Lazy singleton — initialized on first call so import doesn't fail without an API key
_client = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        if not config.GEMINI_API_KEY:
            raise ValueError(
                "GEMINI_API_KEY is not set. Copy .env.example to .env and add your key."
            )
        _client = genai.Client(api_key=config.GEMINI_API_KEY)
    return _client

_SYSTEM_PROMPT = f"""You are a cybersecurity threat intelligence analyst.
Your job is to analyze scraped web content and extract structured threat intelligence.

{config.USER_ZERO_PERSONA}

STRICT RULES:
- If the content is general security discussion, news with no active threat, or completely unrelated: 
  set source_intent=UNKNOWN_DISCUSSION, risk_level=BENIGN, confidence_score below 0.65.
- Do NOT flag legitimate security researchers, educators, or journalists as threats.
- Do NOT hallucinate technical details not present in the source text.
- Be specific and concrete — no generic advice like "be careful online".
- The red_flags and action_checklist must be directly actionable for someone reading this right now.
"""


def _build_user_prompt(raw_title: str | None, raw_content: str | None, source_url: str) -> str:
    return f"""Analyze the following scraped content and extract structured threat intelligence.

SOURCE URL: {source_url}
TITLE: {raw_title or "(no title)"}

CONTENT:
{raw_content or "(no content)"}

Produce a complete ThreatIntelligencePayload. Base your analysis ONLY on the content above.
"""


def _attempt_gemini_call(prompt: str, temperature: float = 0.3) -> Optional[ThreatIntelligencePayload]:
    """Single attempt at a structured Gemini call. Returns None on any failure."""
    try:
        response = _get_client().models.generate_content(
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                temperature=temperature,
                response_mime_type="application/json",
                response_schema=ThreatIntelligencePayload,
            ),
        )
        raw_json = response.text
        payload = ThreatIntelligencePayload.model_validate_json(raw_json)
        return payload

    except ValidationError as e:
        print(f"[EVALUATOR] Pydantic validation error: {e}")
        return None
    except Exception as e:
        print(f"[EVALUATOR] Gemini API error: {e}")
        return None


def _apply_confidence_fallback(payload: ThreatIntelligencePayload) -> ThreatIntelligencePayload:
    """
    If confidence is below the floor, downgrade risk and intent.
    Prevents low-quality or ambiguous analysis from triggering alerts.
    """
    if payload.confidence_score < config.CONFIDENCE_FLOOR:
        print(
            f"[EVALUATOR] Low confidence ({payload.confidence_score:.2f}) — "
            f"downgrading '{payload.threat_title}' to LOW / UNKNOWN_DISCUSSION."
        )
        # Return a new instance with downgraded fields (Pydantic models are immutable)
        return payload.model_copy(update={
            "risk_level": "LOW",
            "source_intent": "UNKNOWN_DISCUSSION",
            "unmatched_reason": payload.unmatched_reason or (
                f"Confidence score {payload.confidence_score:.2f} below threshold {config.CONFIDENCE_FLOOR}. "
                "Content may be ambiguous, educational, or unrelated."
            ),
        })
    return payload


async def evaluate_threat(
    raw_title: str | None,
    raw_content: str | None,
    source_url: str,
) -> Optional[ThreatIntelligencePayload]:
    """
    Main evaluator entry point.
    Returns a validated ThreatIntelligencePayload or None on unrecoverable failure.
    """
    prompt = _build_user_prompt(raw_title, raw_content, source_url)

    # Attempt 1: Normal call
    payload = _attempt_gemini_call(prompt, temperature=0.3)

    # Fallback attempt 2: Retry at temperature=0.0 (deterministic)
    if payload is None:
        print("[EVALUATOR] Retrying with temperature=0.0 ...")
        payload = _attempt_gemini_call(prompt, temperature=0.0)

    if payload is None:
        print(f"[EVALUATOR] FAILED_PARSING after retry for URL: {source_url}")
        return None

    # Apply confidence floor fallback
    payload = _apply_confidence_fallback(payload)

    print(
        f"[EVALUATOR] ✓ '{payload.threat_title}' | "
        f"Risk={payload.risk_level} | Relevance={payload.relevance_score}/10 | "
        f"Confidence={payload.confidence_score:.2f}"
    )
    return payload
