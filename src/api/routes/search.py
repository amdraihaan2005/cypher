from typing import List, Optional
from fastapi import APIRouter, Depends, Query

from src.mitre.db import MitreRepository
from src.search.hybrid import HybridSearchEngine
from src.api.schemas import SearchResponse, HybridSearchResponse, ScoredEntityItem

router = APIRouter(prefix="/api/search", tags=["Search"])

_hybrid_engine: Optional[HybridSearchEngine] = None


def get_hybrid_engine() -> HybridSearchEngine:
    global _hybrid_engine
    if _hybrid_engine is None:
        _hybrid_engine = HybridSearchEngine()
    return _hybrid_engine


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="Fast Unified Entity Search", response_model=SearchResponse)
def search(
    q: str = Query(..., min_length=1, description="Search term across techniques, groups, and software"),
    limit: int = Query(15, ge=1, le=100, description="Max results per category"),
    repo: MitreRepository = Depends(get_repo),
):
    """Searches techniques, adversary groups, and malware/software tools for the given keyword."""
    try:
        results = repo.search_all(query=q, limit=limit)
        return SearchResponse(
            query=q,
            techniques=results["techniques"],
            groups=results["groups"],
            software=results["software"],
        )
    finally:
        repo.close()


@router.get("/semantic", summary="Dense Semantic Vector Search", response_model=HybridSearchResponse)
def search_semantic(
    q: str = Query(..., min_length=1, description="Natural language question, threat actor behavior, or attack scenario"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type: technique, group, software, mitigation, tactic"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of items to return"),
    engine: HybridSearchEngine = Depends(get_hybrid_engine),
):
    """
    Understands cybersecurity concepts across all 1,757 MITRE entities via FastEmbed dense vectors.
    Examples:
    - 'Russian military intelligence targeting energy grids' -> Sandworm Team (group)
    - 'Ransomware deleting shadow copies' -> Inhibit System Recovery (technique)
    - 'In-memory credential dumping tool' -> Mimikatz (software)
    """
    results = engine.search_dense(query=q, entity_type=entity_type, limit=limit)
    items = []
    for r in results:
        tech = r.detail.technique if hasattr(r.detail, "technique") else None
        items.append(
            ScoredEntityItem(
                entity_id=r.entity_id,
                entity_type=r.entity_type,
                name=r.name,
                score=r.score,
                dense_score=r.dense_score,
                sparse_score=r.sparse_score,
                technique=tech,
            )
        )
    return HybridSearchResponse(
        query=q,
        mode="semantic",
        entity_type=entity_type,
        total=len(items),
        results=items,
    )


@router.get("/sparse", summary="Sparse BM25 Keyword Search", response_model=HybridSearchResponse)
def search_sparse(
    q: str = Query(..., min_length=1, description="Keywords, exact technique IDs (T1059.001), group aliases, or tool names"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type: technique, group, software, mitigation, tactic"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of items to return"),
    engine: HybridSearchEngine = Depends(get_hybrid_engine),
):
    """
    Executes an exact token BM25 search across all 1,757 MITRE entities via SQLite FTS5.
    Examples: 'T1059.001' or 'Cozy Bear' or 'Mimikatz' or 'M1032'
    """
    results = engine.search_sparse(query=q, entity_type=entity_type, limit=limit)
    items = []
    for r in results:
        tech = r.detail.technique if hasattr(r.detail, "technique") else None
        items.append(
            ScoredEntityItem(
                entity_id=r.entity_id,
                entity_type=r.entity_type,
                name=r.name,
                score=r.score,
                dense_score=r.dense_score,
                sparse_score=r.sparse_score,
                technique=tech,
            )
        )
    return HybridSearchResponse(
        query=q,
        mode="sparse",
        entity_type=entity_type,
        total=len(items),
        results=items,
    )


@router.get("/hybrid", summary="Combined Hybrid Semantic + BM25 Search", response_model=HybridSearchResponse)
def search_hybrid(
    q: str = Query(..., min_length=1, description="Query string combining concepts and technical terms"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type: technique, group, software, mitigation, tactic"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of items to return"),
    alpha: float = Query(0.6, ge=0.0, le=1.0, description="Weight for dense semantic search (1.0=pure dense, 0.0=pure sparse)"),
    engine: HybridSearchEngine = Depends(get_hybrid_engine),
):
    """
    Combines dense semantic vector search with sparse BM25 token matching across all 1,757 MITRE entities.
    Score = alpha * dense_score + (1 - alpha) * sparse_score.
    """
    results = engine.search_hybrid(query=q, entity_type=entity_type, limit=limit, alpha=alpha)
    items = []
    for r in results:
        tech = r.detail.technique if hasattr(r.detail, "technique") else None
        items.append(
            ScoredEntityItem(
                entity_id=r.entity_id,
                entity_type=r.entity_type,
                name=r.name,
                score=r.score,
                dense_score=r.dense_score,
                sparse_score=r.sparse_score,
                technique=tech,
            )
        )
    return HybridSearchResponse(
        query=q,
        mode="hybrid",
        entity_type=entity_type,
        total=len(items),
        results=items,
    )


@router.get("/rrf", summary="Reciprocal Rank Fusion (RRF) Search", response_model=HybridSearchResponse)
def search_rrf(
    q: str = Query(..., min_length=1, description="Query string combining concepts, keywords, or incident descriptions"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type: technique, group, software, mitigation, tactic"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of items to return"),
    k: int = Query(60, ge=1, le=200, description="RRF smoothing constant (default: 60)"),
    engine: HybridSearchEngine = Depends(get_hybrid_engine),
):
    """
    Executes rank-based fusion (RRF) merging dense and sparse retrieval channels:
    RRF Score = sum(1 / (k + rank)).
    Distribution-agnostic and scale-invariant.
    """
    results = engine.search_rrf(query=q, entity_type=entity_type, limit=limit, k=k)
    items = []
    for r in results:
        tech = r.detail.technique if hasattr(r.detail, "technique") else None
        items.append(
            ScoredEntityItem(
                entity_id=r.entity_id,
                entity_type=r.entity_type,
                name=r.name,
                score=r.score,
                dense_score=r.dense_score,
                sparse_score=r.sparse_score,
                technique=tech,
            )
        )
    return HybridSearchResponse(
        query=q,
        mode="rrf",
        entity_type=entity_type,
        total=len(items),
        results=items,
    )
