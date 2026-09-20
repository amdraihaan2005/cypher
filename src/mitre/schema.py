from typing import List, Optional
from pydantic import BaseModel, Field


class TacticItem(BaseModel):
    stix_id: str
    attack_id: str
    name: str
    shortname: str
    description: str
    url: Optional[str] = None


class TechniqueItem(BaseModel):
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


class MitigationItem(BaseModel):
    stix_id: str
    attack_id: str
    name: str
    description: str
    url: Optional[str] = None


class GroupItem(BaseModel):
    stix_id: str
    attack_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    description: str
    url: Optional[str] = None


class SoftwareItem(BaseModel):
    stix_id: str
    attack_id: str
    name: str
    type: str  # 'malware' or 'tool'
    aliases: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    description: str
    url: Optional[str] = None


class TechniqueDetail(BaseModel):
    technique: TechniqueItem
    subtechniques: List[TechniqueItem] = Field(default_factory=list)
    mitigations: List[MitigationItem] = Field(default_factory=list)
    groups: List[GroupItem] = Field(default_factory=list)
    software: List[SoftwareItem] = Field(default_factory=list)


class TacticDetail(BaseModel):
    tactic: TacticItem
    techniques: List[TechniqueItem] = Field(default_factory=list)


class MitigationDetail(BaseModel):
    mitigation: MitigationItem
    techniques: List[TechniqueItem] = Field(default_factory=list)


class GroupDetail(BaseModel):
    group: GroupItem
    techniques: List[TechniqueItem] = Field(default_factory=list)
    software: List[SoftwareItem] = Field(default_factory=list)


class SoftwareDetail(BaseModel):
    software: SoftwareItem
    techniques: List[TechniqueItem] = Field(default_factory=list)
    groups: List[GroupItem] = Field(default_factory=list)
