"""
web/app.py — FastAPI dashboard backend.

Routes:
  GET /           → Threat Feed (threat cards + scraper health telemetry)
  GET /api/threats → JSON feed of recent threats
  GET /api/telemetry → JSON scraper health log
  GET /api/stats  → Dashboard summary stats
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from db.database import (
    get_recent_threats,
    get_telemetry_log,
    get_dashboard_stats,
)

app = FastAPI(title="Threat Radar", docs_url=None, redoc_url=None)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Serve static files (CSS, JS)
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page — renders the full threat feed + telemetry."""
    threats = await get_recent_threats(limit=20)
    telemetry = await get_telemetry_log(limit=20)
    stats = await get_dashboard_stats()

    # Parse JSON fields for template rendering
    import json
    for t in threats:
        t["red_flags"] = json.loads(t.get("red_flags") or "[]")
        t["action_checklist"] = json.loads(t.get("action_checklist") or "[]")

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "threats": threats,
            "telemetry": telemetry,
            "stats": stats,
        },
    )


@app.get("/api/threats")
async def api_threats():
    """JSON endpoint for recent threat reports."""
    import json
    threats = await get_recent_threats(limit=50)
    for t in threats:
        t["red_flags"] = json.loads(t.get("red_flags") or "[]")
        t["action_checklist"] = json.loads(t.get("action_checklist") or "[]")
    return JSONResponse(content=threats)


@app.get("/api/telemetry")
async def api_telemetry():
    """JSON endpoint for scraper health telemetry."""
    data = await get_telemetry_log(limit=50)
    return JSONResponse(content=data)


@app.get("/api/stats")
async def api_stats():
    """JSON endpoint for summary stats."""
    stats = await get_dashboard_stats()
    return JSONResponse(content=stats)


@app.post("/api/simulate-heal")
async def api_simulate_heal():
    """Endpoint to trigger a simulated scraper breakdown and auto-healing cycle for demo."""
    import config
    from db.database import log_telemetry

    collector_id = config.GITHUB_ADVISORIES_COLLECTOR_ID or "c_msyg5sxi184fzgx1s9"
    # Step 1: Log degraded state
    await log_telemetry(
        collector_id=collector_id,
        source_name="github_advisories",
        target_url="https://github.com/advisories",
        status="DEGRADED",
        error_message="Simulated DOM mutation: advisory element selectors corrupted",
        heal_triggered=True,
    )
    # Step 2: Log healed state after recovery
    await log_telemetry(
        collector_id=collector_id,
        source_name="github_advisories",
        target_url="https://github.com/advisories",
        status="HEALED",
        items_found=25,
        items_new=5,
        heal_triggered=True,
    )
    updated_stats = await get_dashboard_stats()
    return JSONResponse(content={"status": "success", "message": "Self-healing triggered & logged successfully", "stats": updated_stats})
