"""AMCDS dashboard server — one-command launch.

Usage
-----
    python serve.py
        → If no results/demo_report.json exists, runs the simulation first.
        → Starts a local web server at http://127.0.0.1:8000
        → Auto-opens your browser at the live dashboard.

Endpoints
---------
GET  /                  → the cinematic dashboard
GET  /api/report        → the latest demo_report.json
POST /api/regenerate    → re-runs run_demo.py (so the dashboard "Regenerate"
                          button can refresh the simulation without leaving
                          the browser)
GET  /api/health        → liveness check (used by dashboard on connect)
GET  /static/*          → dashboard static assets (CSS, JS — currently none,
                          everything is inlined in the HTML)

Why this exists
---------------
Opening dashboard/index.html directly via file:// breaks because the browser
refuses to fetch sibling JSON files for security (CORS). A tiny local HTTP
server fixes that without adding any heavy infra.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles


HERE = Path(__file__).parent.resolve()
DASHBOARD_DIR = HERE / "dashboard"
RESULTS_DIR = HERE / "results"
REPORT_PATH = RESULTS_DIR / "demo_report.json"


def ensure_report(scenarios_per_type: int = 15, quantum_sample: int = 3) -> None:
    """If no report exists yet, run the demo so the dashboard has data."""
    if REPORT_PATH.exists() and REPORT_PATH.stat().st_size > 0:
        return
    print("📊 No demo_report.json — running an initial simulation "
          f"({scenarios_per_type*3} benchmark scenarios)…")
    subprocess.run(
        [sys.executable, str(HERE / "run_demo.py"),
         "--scenarios-per-type", str(scenarios_per_type),
         "--quantum-sample", str(quantum_sample)],
        cwd=str(HERE), check=True,
    )


def create_app() -> FastAPI:
    app = FastAPI(title="AMCDS Live Dashboard",
                  description="Local server for the cinematic AMCDS demo")
    # Permissive CORS for localhost development.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"], allow_credentials=False,
        allow_methods=["*"], allow_headers=["*"],
    )

    @app.get("/")
    def index():
        return FileResponse(DASHBOARD_DIR / "index.html")

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "report_exists": REPORT_PATH.exists(),
            "report_path": str(REPORT_PATH),
        }

    @app.get("/api/report")
    def report():
        if not REPORT_PATH.exists():
            raise HTTPException(404, "No report yet — POST /api/regenerate first.")
        return FileResponse(REPORT_PATH, media_type="application/json")

    @app.post("/api/regenerate")
    def regenerate(scenarios_per_type: int = 15, quantum_sample: int = 3):
        """Re-run the simulation and return the new report."""
        try:
            subprocess.run(
                [sys.executable, str(HERE / "run_demo.py"),
                 "--scenarios-per-type", str(scenarios_per_type),
                 "--quantum-sample", str(quantum_sample)],
                cwd=str(HERE), check=True, timeout=180,
                capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            raise HTTPException(500, f"run_demo.py failed: {e.stderr[-1000:]}")
        except subprocess.TimeoutExpired:
            raise HTTPException(504, "Regeneration timed out after 180s")
        return JSONResponse({"status": "regenerated",
                             "report_path": str(REPORT_PATH)})

    # Serve any static assets we might add later.
    if DASHBOARD_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)),
                  name="static")

    return app


def open_browser_after(url: str, delay: float = 1.0) -> None:
    time.sleep(delay)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't auto-open browser")
    parser.add_argument("--no-initial-run", action="store_true",
                        help="Don't run the demo even if no report exists")
    args = parser.parse_args()

    if not args.no_initial_run:
        ensure_report()

    url = f"http://{args.host}:{args.port}"
    banner = "═" * 64
    print(f"\n{banner}\n  🚀  AMCDS Live Dashboard\n  {url}\n{banner}\n"
          f"   Press Ctrl+C to stop.\n")
    if not args.no_browser:
        threading.Thread(target=open_browser_after, args=(url,),
                         daemon=True).start()

    app = create_app()
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
