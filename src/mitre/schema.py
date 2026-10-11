from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class MitreBaseModel(BaseModel):
    """Base model configured for Pydantic v2 attribute mapping and serialization."""
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class TacticItem(MitreBaseModel):
    stix_id: str
    attack_id: str
    name: str
    shortname: str
    description: str
    url: Optional[str] = None


class TechniqueItem(MitreBaseModel):
    stix_id: str
    attack_id: str
    name: str
    description: str
    is_subtechnique: bool = False
    parent_attack_id: Optional[str] = None
    tactics: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    detection: Optional[str] = None
    url: Optional[str] = None


class MitigationItem(MitreBaseModel):
    stix_id: str
    attack_id: str
    name: str
    description: str
    url: Optional[str] = None


class GroupItem(MitreBaseModel):
    stix_id: str
    attack_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: str
    url: Optional[str] = None


class SoftwareItem(MitreBaseModel):
    stix_id: str
    attack_id: str
    name: str
    type: str  # 'malware' or 'tool'
    aliases: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    description: str
    url: Optional[str] = None


class TechniqueDetail(MitreBaseModel):
    technique: TechniqueItem
    subtechniques: List[TechniqueItem] = Field(default_factory=list)
    mitigations: List[MitigationItem] = Field(default_factory=list)
    groups: List[GroupItem] = Field(default_factory=list)
    software: List[SoftwareItem] = Field(default_factory=list)


class TacticDetail(MitreBaseModel):
    tactic: TacticItem
    techniques: List[TechniqueItem] = Field(default_factory=list)


class MitigationDetail(MitreBaseModel):
    mitigation: MitigationItem
    techniques: List[TechniqueItem] = Field(default_factory=list)


class GroupDetail(MitreBaseModel):
    group: GroupItem
    techniques: List[TechniqueItem] = Field(default_factory=list)
    software: List[SoftwareItem] = Field(default_factory=list)


class SoftwareDetail(MitreBaseModel):
    software: SoftwareItem
    techniques: List[TechniqueItem] = Field(default_factory=list)
    groups: List[GroupItem] = Field(default_factory=list)


__all__ = [
    "MitreBaseModel",
    "TacticItem",
    "TechniqueItem",
    "MitigationItem",
    "GroupItem",
    "SoftwareItem",
    "TechniqueDetail",
    "TacticDetail",
    "MitigationDetail",
    "GroupDetail",
    "SoftwareDetail",
]

