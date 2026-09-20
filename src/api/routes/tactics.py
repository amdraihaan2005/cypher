from typing import List
from fastapi import APIRouter, Depends, HTTPException, Path

from src.mitre.db import MitreRepository
from src.mitre.schema import TacticItem, TacticDetail

router = APIRouter(prefix="/api/tactics", tags=["Tactics"])


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="List all 15 MITRE ATT&CK Tactics", response_model=List[TacticItem])
def list_tactics(repo: MitreRepository = Depends(get_repo)):
    """Retrieve all Enterprise ATT&CK tactics in standard order."""
    try:
        return repo.list_tactics()
    finally:
        repo.close()


@router.get("/{identifier}", summary="Get Tactic detail by ID or Shortname", response_model=TacticDetail)
def get_tactic(
    identifier: str = Path(..., description="Tactic ATT&CK ID (e.g. TA0001) or shortname (e.g. initial-access)"),
    repo: MitreRepository = Depends(get_repo),
):
    """Retrieve a tactic and all techniques categorized under it."""
    try:
        detail = repo.get_tactic(identifier)
        if not detail:
            raise HTTPException(
                status_code=404,
                detail=f"Tactic '{identifier}' not found in Enterprise ATT&CK.",
            )
        return detail
    finally:
        repo.close()
