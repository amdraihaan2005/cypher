from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Path

from src.mitre.db import MitreRepository
from src.mitre.schema import SoftwareItem, SoftwareDetail
from src.api.schemas import PaginatedResponse

router = APIRouter(prefix="/api/software", tags=["Software & Malware"])


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="List Malware & Dual-Use Software Tools", response_model=PaginatedResponse[SoftwareItem])
def list_software(
    type: Optional[str] = Query(None, description="Filter by software type: 'malware' or 'tool'"),
    platform: Optional[str] = Query(None, description="Filter by platform (e.g. 'Windows', 'Linux', 'macOS')"),
    limit: int = Query(50, ge=1, le=200, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve catalog of malware and dual-use software tools cataloged by MITRE."""
    try:
        items, total = repo.list_software(limit=limit, offset=offset, type=type, platform=platform)
        return PaginatedResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            has_more=(offset + len(items)) < total,
        )
    finally:
        repo.close()


@router.get("/{attack_id}", summary="Get Software Profile and Techniques Implemented", response_model=SoftwareDetail)
def get_software(
    attack_id: str = Path(..., description="Software ID (e.g. 'S0002' for Mimikatz)"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve software details, platform support, and techniques it is known to execute."""
    try:
        detail = repo.get_software(attack_id)
        if not detail:
            raise HTTPException(
                status_code=404,
                detail=f"Software/malware '{attack_id}' not found in Enterprise ATT&CK.",
            )
        return detail
    finally:
        repo.close()
