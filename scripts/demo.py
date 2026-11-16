"""Run SecureAIOps in self-contained demo mode.

No API key, no database server required: uses the deterministic offline
engine, local BM25 retrieval and a throw-away SQLite audit store.

    python scripts/demo.py            # http://127.0.0.1:8000
    python scripts/demo.py --port 9000
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--live", action="store_true", help="use Gemini from .env instead of the offline engine")
    args = parser.parse_args()

    (ROOT / "data").mkdir(exist_ok=True)
    os.environ.setdefault("APP_ENV", "development")
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{(ROOT / 'data' / 'demo.db').as_posix()}")
    os.environ.setdefault("KB_BACKEND", "local")
    os.environ.setdefault("LLM_PROVIDER", "auto" if args.live else "offline")
    os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "120")

    import uvicorn

    uvicorn.run("app.main:app", host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
