import os
from contextlib import asynccontextmanager
from typing import Dict, Optional
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Depends
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
from src.api.routes.intelligence import get_reasoning_engine

from src.api.dependencies import get_repo

_cached_stats: Optional[Dict[str, int]] = None


def get_cached_statistics() -> Dict[str, int]:
    global _cached_stats
    if _cached_stats is None:
        with MitreRepository() as repo:
            _cached_stats = repo.get_statistics()
    return _cached_stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        get_cached_statistics()
    except Exception as e:
        print(f"[Lifespan] Database initialization warning: {e}")

    try:
        engine = get_reasoning_engine()
        # Pre-warm the FastEmbed ONNX model so the first request isn't slow.
        # engine.search_engine.dense is the DenseSearchEngine instance.
        _ = engine.search_engine.dense.model
        print("[Lifespan] Core threat intelligence engine pre-warmed successfully.")
    except Exception as e:
        print(f"[Lifespan] Warning: Pre-warming embedding model failed: {e}")
    yield

    try:
        search.close_hybrid_engine()
        intelligence.close_reasoning_engine()
        print("[Lifespan] Engines and connections closed cleanly.")
    except Exception:
        pass


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
        lifespan=lifespan,
    )

    cors_raw = os.getenv("CORS_ORIGINS", "*")
    cors_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
    is_wildcard = cors_origins == ["*"] or not cors_origins

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if is_wildcard else cors_origins,
        allow_credentials=False if is_wildcard else True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

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
        return RedirectResponse(url="/docs")

    @app.get("/health", summary="Service Health Check", response_model=HealthResponse, tags=["System"])
    def health_check(repo: MitreRepository = Depends(get_repo)):
        try:
            repo.conn.execute("SELECT 1").fetchone()
            return HealthResponse(
                status="healthy",
                version="1.0.0",
                database_connected=True,
                statistics=get_cached_statistics(),
            )
        except Exception as e:
            return HealthResponse(
                status=f"degraded: {str(e)}",
                version="1.0.0",
                database_connected=False,
                statistics={},
            )

    return app


app = create_app()
