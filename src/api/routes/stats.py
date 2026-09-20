from typing import Dict
from fastapi import APIRouter, Depends

from src.mitre.db import MitreRepository

router = APIRouter(prefix="/api/stats", tags=["Statistics"])


def get_repo() -> MitreRepository:
    return MitreRepository()


@router.get("", summary="Get MITRE ATT&CK Database Statistics", response_model=Dict[str, int])
def get_stats(repo: MitreRepository = Depends(get_repo)):
    """Returns total count of tactics, techniques, mitigations, groups, software, and relationships."""
    try:
        return repo.get_statistics()
    finally:
        repo.close()
