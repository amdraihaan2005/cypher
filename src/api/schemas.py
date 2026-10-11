from typing import List, Generic, TypeVar, Optional, Dict
from pydantic import Field

from src.mitre.schema import (
    MitreBaseModel,
    TacticItem,
    TechniqueItem,
    MitigationItem,
    GroupItem,
    SoftwareItem,
    TechniqueDetail,
    TacticDetail,
    MitigationDetail,
    GroupDetail,
    SoftwareDetail,
)

T = TypeVar("T")


class PaginatedResponse(MitreBaseModel, Generic[T]):
    items: List[T]
    total: int
    limit: int
    offset: int
    has_more: bool


class SearchResponse(MitreBaseModel):
    query: str
    techniques: List[TechniqueItem] = Field(default_factory=list)
    groups: List[GroupItem] = Field(default_factory=list)
    software: List[SoftwareItem] = Field(default_factory=list)


class HealthResponse(MitreBaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    database_connected: bool
    statistics: Dict[str, int] = Field(default_factory=dict)


class ScoredEntityItem(MitreBaseModel):
    entity_id: str
    entity_type: str  # 'technique', 'tactic', 'mitigation', 'group', 'software'
    name: str
    score: float
    dense_score: Optional[float] = None
    sparse_score: Optional[float] = None
    technique: Optional[TechniqueItem] = None


class HybridSearchResponse(MitreBaseModel):
    query: str
    mode: str  # 'hybrid', 'semantic', 'sparse', 'rrf'
    entity_type: Optional[str] = None
    total: int
    results: List[ScoredEntityItem] = Field(default_factory=list)


__all__ = [
    "PaginatedResponse",
    "SearchResponse",
    "HealthResponse",
    "ScoredEntityItem",
    "HybridSearchResponse",
]
