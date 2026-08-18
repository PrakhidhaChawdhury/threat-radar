import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from db.database import init_db, get_dashboard_stats
from engine.heuristics import run_heuristic_gate

async def test():
    # 1. Test DB Init
    await init_db()
    stats = await get_dashboard_stats()
    print(f"[OK] DB init OK -- stats: {stats}")

    # 2. Test Heuristic Gate (Should PASS)
    r = run_heuristic_gate(
        "Need urgent help with this internship",
        "The recruiter asked me to clone this GitHub repo and run npm install to complete my assessment. The repo had a postinstall script that ran curl | sh"
    )
    print(f"[OK] Heuristic test (PASS): passed={r.passed}, buckets={r.matched_buckets}")
    assert r.passed is True

    # 3. Test Heuristic Gate (Should FAIL)
    r2 = run_heuristic_gate(
        "How do I center a div in CSS?",
        "I am trying to center a div horizontally and vertically. I tried using flexbox but it is not working."
    )
    print(f"[OK] Heuristic test (FAIL): passed={r2.passed}, buckets={r2.matched_buckets}")
    assert r2.passed is False

    print("[SUCCESS] ALL TESTS PASSED!")

if __name__ == "__main__":
    asyncio.run(test())
