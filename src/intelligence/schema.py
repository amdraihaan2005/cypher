from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from src.mitre.schema import (
    TechniqueItem,
    GroupItem,
    SoftwareItem,
    MitigationItem,
)


class AttributedGroup(BaseModel):
    group: GroupItem
    matched_techniques: List[str] = Field(description="Technique IDs from the query that this group uses")
    overlap_count: int
    overlap_ratio: float = Field(description="Percentage of query techniques this group is known to use")
    software_used: List[str] = Field(default_factory=list, description="Malware and tools deployed by this group")


class IdentifiedSoftware(BaseModel):
    software: SoftwareItem
    matched_techniques: List[str] = Field(description="Technique IDs implemented by this software")
    match_count: int
    associated_groups: List[str] = Field(default_factory=list, description="Threat groups known to deploy this tool")


class PrioritizedMitigation(BaseModel):
    mitigation: MitigationItem
    mitigated_techniques: List[str] = Field(description="Technique IDs from the attack chain stopped by this control")
    mitigation_count: int
    coverage_percentage: float = Field(description="Percentage of the attack chain stopped by this single control")


class ThreatAnalysisRequest(BaseModel):
    query: str = Field(..., min_length=2, description="Attack scenario, incident alert, or TTP narrative")
    max_techniques: int = Field(5, ge=1, le=20, description="Maximum number of techniques to analyze")
    k: int = Field(60, ge=1, le=200, description="RRF smoothing constant")
    history: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Previous conversation messages in the thread")


class ThreatAnalysisReport(BaseModel):
    query: str
    identified_techniques: List[TechniqueItem] = Field(default_factory=list)
    tactics_involved: List[str] = Field(default_factory=list)
    affected_platforms: List[str] = Field(default_factory=list)
    attributed_groups: List[AttributedGroup] = Field(default_factory=list)
    identified_software: List[IdentifiedSoftware] = Field(default_factory=list)
    prioritized_mitigations: List[PrioritizedMitigation] = Field(default_factory=list)
    detection_data_sources: List[str] = Field(default_factory=list)
    attack_chain_summary: Dict[str, Any] = Field(default_factory=dict)
    ai_answer: Optional[str] = Field(default=None, description="Direct AI answer and tactical intelligence explanation")
    ai_model: Optional[str] = Field(default=None, description="Model used to generate the answer")


class ThreatNarrativeResponse(BaseModel):
    available: bool
    narrative: str
    model: Optional[str] = None


class ThreatChatRequest(BaseModel):
    report: ThreatAnalysisReport
    message: str = Field(..., min_length=1, description="Analyst question or prompt")
    history: List[Dict[str, str]] = Field(default_factory=list, description="Recent conversation turns")


class ThreatChatResponse(BaseModel):
    available: bool
    reply: str
    model: Optional[str] = None
