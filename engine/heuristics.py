"""
engine/heuristics.py — Zero-cost intent-bucket heuristic gate.

Evaluates a COMPOSITE string of (title + content) against broad deception
intent buckets rather than fragile specific keywords. This catches novel
attack vectors (eSIM swaps, QR quishing, fake testnet validators) that
specific tool-name regex would miss.

Returns True  → content warrants LLM evaluation.
Returns False → content is benign, log and skip (save Gemini tokens).
"""

import re
from dataclasses import dataclass


@dataclass
class HeuristicResult:
    passed: bool
    matched_buckets: list[str]
    composite_text_length: int


# ──────────────────────────────────────────────────────────────
# Intent Buckets
# Each bucket targets a category of DECEPTIVE INTENT,
# not a specific tool or platform name.
# ──────────────────────────────────────────────────────────────

_BUCKETS: dict[str, re.Pattern] = {
    # Urgency / Fear / Scarcity — forces emotional panic decision-making
    "URGENCY_SCARCITY": re.compile(
        r"urgent|immediately|suspended|disconnected?|24.?hour|48.?hour|act.?now|"
        r"deadline|expires?|last.?chance|final.?notice|cutoff|action.?required|"
        r"verify.?now|confirm.?identity|account.?blocked|service.?terminated",
        re.IGNORECASE,
    ),

    # Credential / Access / Identity harvesting — what the attacker actually wants
    "CREDENTIAL_REQUEST": re.compile(
        r"otp|one.?time.?pass|seed.?phrase|private.?key|wallet.?connect|"
        r"sign.?transaction|gas.?fee|kyc|aadhaar|pan.?card|scan.?qr|"
        r"install.?profile|mdm.?profile|certificate.?install|two.?factor|2fa.?reset|"
        r"recovery.?phrase|verify.?identity|login.?detail|password.?reset",
        re.IGNORECASE,
    ),

    # Financial / Career Hook — the emotional bait that lowers guard
    "FINANCIAL_CAREER_HOOK": re.compile(
        r"stipend|work.?from.?home|remote.?internship|part.?time|easy.?earn|"
        r"guaranteed.?payout|daily.?commission|airdrop|claim.?reward|"
        r"selected.?for|congratulations.?you|job.?offer|freelance.?project|"
        r"upfront.?fee|registration.?fee|security.?deposit|refundable.?deposit|"
        r"prize.?money|transfer.?fee|processing.?charge",
        re.IGNORECASE,
    ),

    # Unorthodox Technical Workflow — "just run this" social engineering
    "UNORTHODOX_WORKFLOW": re.compile(
        r"npm.?install|pip.?install|postinstall|package\.json|"
        r"download.?apk|install.?app|run.?script|execute.?file|"
        r"clone.?repo|eval\s*\(|curl\s*\|.?sh|wget.+\|.?sh|"
        r"chrome.?extension|vs.?code.?extension|browser.?plugin|"
        r"screen.?share|remote.?access|anydesk|teamviewer|"
        r"send.?money.?first|pay.?to.?unlock",
        re.IGNORECASE,
    ),

    # Developer / Supply Chain attacks — specific to User Zero's toolchain
    "DEVELOPER_SUPPLY_CHAIN": re.compile(
        r"malicious.?package|typosquat|compromised.?repositor|"
        r"fake.?npm|rogue.?extension|supply.?chain|"
        r"github\.com/.+/(?:tool|helper|util|sdk|cli)|"
        r"dependency.?confusion|open.?source.?malware|"
        r"postinstall.?script|malware.?npm|malicious.?pip",
        re.IGNORECASE,
    ),
}


def run_heuristic_gate(raw_title: str | None, raw_content: str | None) -> HeuristicResult:
    """
    Evaluate composite (title + content) string against all intent buckets.

    Key design decision: evaluates `f"{title} {content}"` as a SINGLE string
    so scam signals split across title and body are never missed.
    """
    title = raw_title or ""
    content = raw_content or ""

    # COMPOSITE input — the micro-refinement that catches "Need urgent help 
    # with this internship" (generic title) + scam body
    composite = f"{title} {content}"

    matched_buckets: list[str] = []
    for bucket_name, pattern in _BUCKETS.items():
        if pattern.search(composite):
            matched_buckets.append(bucket_name)

    passed = len(matched_buckets) > 0

    return HeuristicResult(
        passed=passed,
        matched_buckets=matched_buckets,
        composite_text_length=len(composite),
    )
