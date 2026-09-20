from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Path

from src.mitre.db import MitreRepository
from src.mitre.schema import TechniqueItem, TechniqueDetail
from src.api.schemas import PaginatedResponse

router = APIRouter(prefix="/api/techniques", tags=["Techniques"])


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="List & filter MITRE ATT&CK Techniques", response_model=PaginatedResponse[TechniqueItem])
def list_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic shortname (e.g. 'initial-access', 'execution')"),
    platform: Optional[str] = Query(None, description="Filter by platform (e.g. 'Windows', 'Linux', 'macOS', 'IaaS')"),
    is_subtechnique: Optional[bool] = Query(None, description="Filter to only sub-techniques (true) or parent techniques (false)"),
    limit: int = Query(50, ge=1, le=500, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve paginated techniques with optional filtering by tactic, platform, or subtechnique."""
    try:
        items, total = repo.list_techniques(
            limit=limit,
            offset=offset,
            tactic=tactic,
            platform=platform,
            is_subtechnique=is_subtechnique,
        )
        return PaginatedResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(items)) < total,
        )
    finally:
        repo.close()


@router.get("/{attack_id}", summary="Get Technique Deep Graph Detail", response_model=TechniqueDetail)
def get_technique(
    attack_id: str = Path(..., description="Technique or sub-technique ID (e.g. 'T1059' or 'T1059.001')"),
    repo: MitreRepository = Depends(get_repo),
):
    """
    Retrieve full graph view for a technique:
    - Core metadata, description, platforms, and detection guidance
    - Sub-techniques list
    - Defensive mitigations (courses of action)
    - Adversary groups (APTs) known to utilize it
    - Software/malware implementing it
    """
    try:
        detail = repo.get_technique(attack_id)
        if not detail:
            raise HTTPException(
                status_code=404,
                detail=f"Technique '{attack_id}' not found in Enterprise ATT&CK.",
            )
        return detail
    finally:
        repo.close()
