"""
CloudSentinel FastAPI application.

Run locally:
    uvicorn cloudsentinel.api.app:app --reload
"""

from typing import Dict

from fastapi import FastAPI

from cloudsentinel import __version__
from cloudsentinel.api.routes import findings, rules, scans
from cloudsentinel.api.schemas import HealthResponse


def create_app() -> FastAPI:
    """Build the FastAPI application."""
    app = FastAPI(
        title="CloudSentinel API",
        version=__version__,
        description="AWS IAM security analysis built on the IAM Misconfiguration Scanner.",
    )

    @app.get("/health", response_model=HealthResponse, tags=["health"])
    def health() -> Dict[str, str]:
        return {"status": "ok"}

    app.include_router(scans.router)
    app.include_router(rules.router)
    app.include_router(findings.router)
    return app


app = create_app()
