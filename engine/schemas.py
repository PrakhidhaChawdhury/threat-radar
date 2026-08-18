"""
engine/schemas.py — Pydantic model for Gemini's structured threat output.
This is the contract between the LLM and the rest of the pipeline.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ThreatIntelligencePayload(BaseModel):
    """
    Structured threat intelligence extracted by Gemini 3.7 Flash.
    Every field has an explicit description that appears in the Gemini prompt.
    """

    source_intent: str = Field(
        description=(
            "Classify the PRIMARY purpose of the source content. "
            "ACTIVE_LURE = the content IS the scam (a malicious post/link/repo actively targeting victims). "
            "VICTIM_REPORT = a person describing a scam they encountered or were targeted by. "
            "EDUCATIONAL_ADVISORY = security researcher, news outlet, or official body explaining a threat. "
            "UNKNOWN_DISCUSSION = none of the above, general chatter, or unrelated content."
        )
    )

    risk_level: str = Field(
        description=(
            "Severity of this threat if the target user were to fall for it. "
            "CRITICAL = immediate financial or account loss possible (credential theft, financial fraud, malware execution). "
            "HIGH = significant risk with delayed or secondary damage (data exposure, persistent malware). "
            "MEDIUM = moderate risk, usually recoverable (spam, phishing attempts caught early). "
            "LOW = minimal risk (general awareness, historical patterns). "
            "BENIGN = not a threat at all."
        )
    )

    threat_category: str = Field(
        description=(
            "The specific attack domain. Examples: "
            "'Fake Internship / Job Scam', 'Developer Tooling Compromise (npm/pip/VS Code)', "
            "'UPI / Financial Phishing', 'Task & Deposit Scam (Telegram)', "
            "'Fake Courier / Delivery Fee', 'Malicious GitHub Repository', "
            "'Credential Phishing', 'Social Engineering / Impersonation'."
        )
    )

    threat_title: str = Field(
        description="A punchy, concrete name for this specific attack vector. Maximum 10 words. No generic titles like 'Scam Alert'."
    )

    the_lure: str = Field(
        description="The emotional, financial, or professional hook the attacker uses to get the victim's attention and initial trust."
    )

    the_hidden_trap: str = Field(
        description="What actually happens under the hood once the victim takes the bait. Be technically precise."
    )

    red_flags: List[str] = Field(
        min_length=2,
        max_length=4,
        description="2 to 4 concrete, specific indicators that would let the target user identify this threat in the wild."
    )

    action_checklist: List[str] = Field(
        min_length=1,
        max_length=3,
        description="1 to 3 immediate, actionable verification steps the user can take right now to stay safe."
    )

    relevance_score: int = Field(
        ge=1,
        le=10,
        description=(
            "How directly relevant is this threat to the TARGET USER PROFILE provided? "
            "10 = directly targets a student/early-career developer in India using the exact tools they use daily. "
            "5 = moderately relevant, could apply but not a direct match. "
            "1 = enterprise/nation-state level threat completely outside their context."
        )
    )

    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Your confidence that this content represents a genuine, actionable threat. "
            "1.0 = absolutely certain (active malware repo, confirmed fraud campaign). "
            "0.7 = likely but some ambiguity. "
            "Below 0.65 = uncertain — use UNKNOWN_DISCUSSION intent and LOW risk."
        )
    )

    unmatched_reason: Optional[str] = Field(
        default=None,
        description="If confidence_score < 0.65, briefly explain why this content does NOT clearly represent an active threat."
    )
