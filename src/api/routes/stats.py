from typing import Dict
from fastapi import APIRouter, Depends

from src.mitre.db import MitreRepository
from src.api.dependencies import get_repo

router = APIRouter(prefix="/api/stats", tags=["Statistics"])


@router.get("", summary="Get MITRE ATT&CK Database Statistics", response_model=Dict[str, int])
def get_stats(repo: MitreRepository = Depends(get_repo)):
    """Returns total count of tactics, techniques, mitigations, groups, software, and relationships."""
    return repo.get_statistics()
