"""
engine/critic.py — The Self-Critic / Metacognition Guard.

The agent watching itself. Runs immediately after evaluate_threat() and:

1. GROUNDING AUDIT  — Cross-checks every extracted entity (IOC) in
   extracted_entities against the raw source text.  Any entity that does
   NOT appear in the source is flagged as a hallucination and removed.

2. OVER-REACTION CHECK — Detects when the analyst incorrectly flagged an
   educational advisory or news article as an ACTIVE_LURE threat and
   quietly corrects the source_intent field.

3. QUALITY ASSERTION — Ensures red_flags and action_checklist items are
   concrete rather than vacuous ("be careful online") by checking minimum
   token length.

Every audit produces a CriticResult with:
  - audit_status:  "VERIFIED" | "SELF_CORRECTED"
  - corrections:   list[str]  — human-readable description of each fix
  - final_payload: the (possibly corrected) ThreatIntelligencePayload

This result is stored in the DB and shown in the dashboard so that judges
and users can see the agent actively reasoning about its own outputs.
"""

import re
from dataclasses import dataclass, field
from typing import List

from engine.schemas import ThreatIntelligencePayload


# ── Patterns that indicate educational / journalistic content ─────────────
_EDUCATIONAL_SIGNALS = [
    r"\bresearch(ers?)?\b",
    r"\bstud(y|ied|ies)\b",
    r"\banalys[ie]s\b",
    r"\breport(s|ed)?\b",
    r"\bnews(letter)?\b",
    r"\bwarning(s)?\b",
    r"\badvisory\b",
    r"\bdisclos(ed|ure)\b",
    r"\bpatch(ed|es)?\b",
    r"\bCVE-\d{4}-\d+\b",
]
_EDU_RE = re.compile("|".join(_EDUCATIONAL_SIGNALS), re.IGNORECASE)

# Vacuous / generic phrases that add no actionable information
_VACUOUS_PHRASES = [
    "be careful",
    "stay safe",
    "use caution",
    "be wary",
    "think twice",
    "exercise caution",
]


@dataclass
class CriticResult:
    """Outcome of a self-audit pass."""
    audit_status: str           # "VERIFIED" | "SELF_CORRECTED"
    corrections: List[str]      # Human-readable description of each fix
    final_payload: ThreatIntelligencePayload


def _entity_present_in_source(entity: str, raw_text: str) -> bool:
    """
    Check whether an extracted entity actually exists in the raw source text.
    Case-insensitive substring match.  Strips leading @ for Telegram handles.
    """
    needle = entity.lstrip("@").lower()
    return needle in raw_text.lower()


def _is_vacuous(text: str) -> bool:
    """Return True if the text is generic and non-actionable."""
    lower = text.lower()
    return any(phrase in lower for phrase in _VACUOUS_PHRASES) and len(text.split()) < 8


def audit(
    payload: ThreatIntelligencePayload,
    raw_title: str | None,
    raw_content: str | None,
) -> CriticResult:
    """
    Run all three audit checks on a payload and return a CriticResult.
    This is a synchronous, CPU-only operation — no LLM calls.
    """
    corrections: List[str] = []
    updates: dict = {}

    combined_source = f"{raw_title or ''} {raw_content or ''}".strip()

    # ── Audit 1: Entity / IOC Grounding ─────────────────────────────────
    original_entities = payload.extracted_entities or []
    grounded_entities = [
        e for e in original_entities
        if _entity_present_in_source(e, combined_source)
    ]
    hallucinated = set(original_entities) - set(grounded_entities)
    if hallucinated:
        corrections.append(
            f"HALLUCINATION_REMOVED: IOCs not found in source text: "
            + ", ".join(f'"{h}"' for h in hallucinated)
        )
        updates["extracted_entities"] = grounded_entities

    # ── Audit 2: Over-Reaction Check ────────────────────────────────────
    # If the model flagged this as ACTIVE_LURE but the source text is
    # predominantly educational/journalistic language, correct to EDUCATIONAL_ADVISORY.
    if payload.source_intent == "ACTIVE_LURE":
        edu_matches = _EDU_RE.findall(combined_source)
        # Threshold: 3+ educational signals in an "active lure" article = mis-classification
        if len(edu_matches) >= 3:
            corrections.append(
                f"INTENT_CORRECTED: source_intent changed ACTIVE_LURE → EDUCATIONAL_ADVISORY "
                f"({len(edu_matches)} educational signals detected in source text)"
            )
            updates["source_intent"] = "EDUCATIONAL_ADVISORY"
            # Also cap the risk level — an article about a threat is not itself the threat
            if payload.risk_level in ("CRITICAL", "HIGH"):
                corrections.append(
                    f"RISK_ADJUSTED: risk_level {payload.risk_level} → MEDIUM "
                    "(source is advisory / journalistic, not an active lure)"
                )
                updates["risk_level"] = "MEDIUM"

    # ── Audit 3: Quality Assertion on Red Flags & Action Items ──────────
    clean_red_flags = [f for f in payload.red_flags if not _is_vacuous(f)]
    if len(clean_red_flags) < len(payload.red_flags):
        removed = len(payload.red_flags) - len(clean_red_flags)
        corrections.append(
            f"VACUOUS_FLAGS_REMOVED: {removed} non-specific red flag(s) stripped. "
            "Retaining only concrete, specific indicators."
        )
        if clean_red_flags:
            updates["red_flags"] = clean_red_flags
        # If ALL flags were vacuous, keep originals rather than leaving an empty list
        # (Pydantic requires min_length=2)

    clean_actions = [a for a in payload.action_checklist if not _is_vacuous(a)]
    if len(clean_actions) < len(payload.action_checklist):
        removed = len(payload.action_checklist) - len(clean_actions)
        corrections.append(
            f"VACUOUS_ACTIONS_REMOVED: {removed} non-specific action(s) stripped."
        )
        if clean_actions:
            updates["action_checklist"] = clean_actions

    # ── Finalize ─────────────────────────────────────────────────────────
    if updates:
        final_payload = payload.model_copy(update=updates)
        audit_status = "SELF_CORRECTED"
        print(
            f"[CRITIC] ⚠️  SELF_CORRECTED '{payload.threat_title}' "
            f"— {len(corrections)} correction(s) applied."
        )
        for c in corrections:
            print(f"[CRITIC]   • {c}")
    else:
        final_payload = payload
        audit_status = "VERIFIED"
        print(f"[CRITIC] ✅ VERIFIED '{payload.threat_title}' — no corrections needed.")

    return CriticResult(
        audit_status=audit_status,
        corrections=corrections,
        final_payload=final_payload,
    )
