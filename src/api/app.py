import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from src.mitre.db import MitreRepository
from src.api.schemas import HealthResponse
from src.api.routes import (
    stats,
    tactics,
    techniques,
    mitigations,
    groups,
    software,
    search,
    intelligence,
)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Cypher AI - MITRE ATT&CK Intelligence API",
        description=(
            "High-performance REST API and knowledge engine for Enterprise MITRE ATT&CK. "
            "Provides unified intelligence across tactics, techniques, sub-techniques, "
            "defensive mitigations, threat groups (APTs), and malware/tools."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS configuration for local development and public frontend (Vercel / Next.js)
    cors_raw = os.getenv("CORS_ORIGINS", "*")
    cors_origins = ["*"] if cors_raw.strip() == "*" else [o.strip() for o in cors_raw.split(",") if o.strip()]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routes
    app.include_router(stats.router)
    app.include_router(tactics.router)
    app.include_router(techniques.router)
    app.include_router(mitigations.router)
    app.include_router(groups.router)
    app.include_router(software.router)
    app.include_router(search.router)
    app.include_router(intelligence.router)

    @app.get("/", include_in_schema=False)
    def root():
        """Redirect root to Swagger UI documentation."""
        return RedirectResponse(url="/docs")

    @app.get("/health", summary="Service Health Check", response_model=HealthResponse, tags=["System"])
    def health_check():
        """Check API service health and verify connectivity to the SQLite MITRE database."""
        repo = MitreRepository()
        try:
            counts = repo.get_statistics()
            return HealthResponse(
                status="healthy",
                version="1.0.0",
                database_connected=True,
                statistics=counts,
            )
        except Exception as e:
            return HealthResponse(
                status=f"degraded: {str(e)}",
                version="1.0.0",
                database_connected=False,
                statistics={},
            )
        finally:
            repo.close()

    @app.on_event("startup")
    def preload_models():
        """Pre-warm the embedding model on startup so the first query isn't slow."""
        try:
            from src.search.dense import DenseSearchEngine
            engine = DenseSearchEngine()
            # Trigger lazy model load by accessing the property
            _ = engine.model
            print("[Startup] Embedding model pre-loaded successfully.")
        except Exception as e:
            print(f"[Startup] Warning: Could not pre-load embedding model: {e}")

    return app


app = create_app()
