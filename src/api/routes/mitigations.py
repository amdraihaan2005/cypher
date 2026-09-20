from fastapi import APIRouter, Depends, HTTPException, Query, Path

from src.mitre.db import MitreRepository
from src.mitre.schema import MitigationItem, MitigationDetail
from src.api.schemas import PaginatedResponse

router = APIRouter(prefix="/api/mitigations", tags=["Mitigations"])


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="List Defensive Mitigations", response_model=PaginatedResponse[MitigationItem])
def list_mitigations(
    limit: int = Query(50, ge=1, le=200, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve defensive controls and mitigations defined in MITRE ATT&CK."""
    try:
        items, total = repo.list_mitigations(limit=limit, offset=offset)
        return PaginatedResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(items)) < total,
        )
    finally:
        repo.close()


@router.get("/{attack_id}", summary="Get Mitigation Detail and Prevented Techniques", response_model=MitigationDetail)
def get_mitigation(
    attack_id: str = Path(..., description="Mitigation ID (e.g. 'M1032' for MFA)"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve a mitigation control along with all attack techniques it blocks."""
    try:
        detail = repo.get_mitigation(attack_id)
        if not detail:
            raise HTTPException(
                status_code=404,
                detail=f"Mitigation '{attack_id}' not found in Enterprise ATT&CK.",
            )
        return detail
    finally:
        repo.close()
