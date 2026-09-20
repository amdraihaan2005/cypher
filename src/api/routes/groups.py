from fastapi import APIRouter, Depends, HTTPException, Query, Path

from src.mitre.db import MitreRepository
from src.mitre.schema import GroupItem, GroupDetail
from src.api.schemas import PaginatedResponse

router = APIRouter(prefix="/api/groups", tags=["Threat Groups (APTs)"])


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="List Adversary Groups / APTs", response_model=PaginatedResponse[GroupItem])
def list_groups(
    limit: int = Query(50, ge=1, le=200, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve catalog of known threat actor groups, APTs, and adversary collectives."""
    try:
        items, total = repo.list_groups(limit=limit, offset=offset)
        return PaginatedResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(items)) < total,
        )
    finally:
        repo.close()


@router.get("/{attack_id}", summary="Get Threat Group Profile and Associated Techniques", response_model=GroupDetail)
def get_group(
    attack_id: str = Path(..., description="Group ATT&CK ID (e.g. 'G0016' for APT29)"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve threat group profile, known aliases, and all attack techniques they employ."""
    try:
        detail = repo.get_group(attack_id)
        if not detail:
            raise HTTPException(
                status_code=404,
                detail=f"Threat group '{attack_id}' not found in Enterprise ATT&CK.",
            )
        return detail
    finally:
        repo.close()
