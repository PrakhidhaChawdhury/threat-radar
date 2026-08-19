"""
config.py — Global constants, thresholds, source definitions, and User Zero persona.
All pipeline components import from here. No magic numbers anywhere else.
"""

import os
import sys
from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

load_dotenv()


# ──────────────────────────────────────────────────────────────
# API Keys
# ──────────────────────────────────────────────────────────────
GEMINI_API_KEY: str = os.environ.get("GEMINI_API_KEY", "")
BRIGHTDATA_API_KEY: str = os.environ.get("BRIGHTDATA_API_KEY", "")
DISCORD_WEBHOOK_URL: str = os.environ.get("DISCORD_WEBHOOK_URL", "")

# ──────────────────────────────────────────────────────────────
# Bright Data Collector IDs
# Each source gets its own Collector ID from Scraper Studio
# ──────────────────────────────────────────────────────────────
GITHUB_ADVISORIES_COLLECTOR_ID: str = os.environ.get("GITHUB_ADVISORIES_COLLECTOR_ID", "")
HACKERNEWS_SECURITY_COLLECTOR_ID: str = os.environ.get("HACKERNEWS_SECURITY_COLLECTOR_ID", "")

# Bright Data REST API base URL
BRIGHTDATA_API_BASE = "https://api.brightdata.com"

# ──────────────────────────────────────────────────────────────
# Alert Thresholds
# ──────────────────────────────────────────────────────────────
RELEVANCE_THRESHOLD: int = int(os.environ.get("RELEVANCE_THRESHOLD", "8"))
RISK_LEVELS_TO_ALERT: list[str] = ["CRITICAL", "HIGH"]
CONFIDENCE_FLOOR: float = 0.65  # Below this → downgrade to LOW / UNKNOWN

# ──────────────────────────────────────────────────────────────
# Pipeline Configuration
# ──────────────────────────────────────────────────────────────
POLLING_INTERVAL_MINUTES: int = int(os.environ.get("POLLING_INTERVAL_MINUTES", "30"))
SANITY_CONTENT_MIN_CHARS: int = 30      # Below this = schema poisoning / over-healing
SANITY_CONTENT_MAX_CHARS: int = 15_000  # Above this = dump / noise page
LLM_MAX_RETRIES: int = 1               # Single retry on Pydantic validation failure

# ──────────────────────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────────────────────
DATABASE_PATH: str = "threat_radar.db"

# ──────────────────────────────────────────────────────────────
# Scraper Sources (Hyper-targeted to User Zero)
# ──────────────────────────────────────────────────────────────
SCRAPER_SOURCES: list[dict] = [
    {
        "name": "github_advisories",
        "label": "GitHub Security Advisories",
        "discovery_url": "https://github.com/advisories",
        "collector_id": GITHUB_ADVISORIES_COLLECTOR_ID,
    },
    {
        "name": "hackernews_security",
        "label": "HackerNews Developer & Gig Threats",
        "discovery_url": "https://news.ycombinator.com",
        "collector_id": HACKERNEWS_SECURITY_COLLECTOR_ID,
    },
]

# ──────────────────────────────────────────────────────────────
# User Zero Persona
# Injected into every Gemini prompt to anchor relevance scoring.
# Keep this specific — it's the single most important personalization lever.
# ──────────────────────────────────────────────────────────────
USER_ZERO_PERSONA = """
TARGET USER PROFILE (User Zero):
- Student / early-career developer in India (Class 12 / College level)
- Actively looking for remote internships, hackathon prizes, freelance gigs
- Regularly uses: LinkedIn, GitHub, Discord, Telegram, Reddit, npm/pip packages, VS Code extensions
- Handles daily UPI payments (Google Pay / PhonePe), online orders, courier tracking
- Participates in hackathons, ambassador programs, developer communities
- Manages modest student bank account (low balance, cost-sensitive)
- Comfortable with code and developer tools but still forming security instincts

VULNERABILITY CONTEXT:
- Eager to prove skills → vulnerable to fake technical assessments/take-homes with malicious repos
- Looking for pocket money → vulnerable to task-and-deposit Telegram scams
- Trusts GitHub/npm by default → vulnerable to typosquatted packages and malicious postinstall scripts
- Expects courier deliveries (hackathon swag, books) → vulnerable to fake redelivery fee SMS
- Urgency/authority triggers → bill payment cutoff APK/SMS phishing, "your account is suspended"
"""

# ──────────────────────────────────────────────────────────────
# Gemini Model
# ──────────────────────────────────────────────────────────────
GEMINI_MODEL: str = "gemini-3.6-flash"
