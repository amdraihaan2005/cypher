from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from mitreattack.stix20 import MitreAttackData

from src.mitre.schema import (
    TacticItem,
    TechniqueItem,
    MitigationItem,
    GroupItem,
    SoftwareItem
)


def _get_external_ref(obj: Any, source_name: str = "mitre-attack") -> Tuple[Optional[str], Optional[str]]:
    """Extracts attack_id and url from STIX external references."""
    external_refs = getattr(obj, "external_references", [])
    attack_id = None
    url = None
    for ref in external_refs:
        ref_source = getattr(ref, "source_name", "")
        if ref_source == source_name:
            attack_id = getattr(ref, "external_id", None)
            url = getattr(ref, "url", None)
            break
        elif not attack_id and hasattr(ref, "external_id"):
            attack_id = getattr(ref, "external_id", None)
            url = getattr(ref, "url", None)
    return attack_id, url


class MitreExtractor:
    """
    Extracts and normalizes MITRE ATT&CK STIX objects into structured dataclasses.
    Uses official MitreAttackData for relationship mappings.
    """

    def __init__(self, stix_filepath: Path):
        self.stix_filepath = Path(stix_filepath)
        if not self.stix_filepath.exists():
            raise FileNotFoundError(f"STIX file not found at: {self.stix_filepath}")
        
        print(f"[MitreExtractor] Initializing MitreAttackData from {self.stix_filepath}...")
        self.mitre = MitreAttackData(str(self.stix_filepath))
        print("[MitreExtractor] MitreAttackData loaded.")

    def extract_tactics(self) -> List[TacticItem]:
        tactics_raw = self.mitre.get_tactics(remove_revoked_deprecated=True)
        results = []
        for t in tactics_raw:
            attack_id, url = _get_external_ref(t)
            shortname = getattr(t, "x_mitre_shortname", "")
            results.append(
                TacticItem(
                    stix_id=t.id,
                    attack_id=attack_id or shortname,
                    name=t.name,
                    shortname=shortname,
                    description=getattr(t, "description", "") or "",
                    url=url,
                )
            )
        return results

    def extract_techniques(self) -> Tuple[List[TechniqueItem], Dict[str, str]]:
        """
        Extracts all Enterprise techniques and sub-techniques.
        Returns:
            techniques: list of TechniqueItem
            stix_to_attack_id: map of stix_id -> attack_id for fast relationship resolution
        """
        techniques_raw = self.mitre.get_techniques(remove_revoked_deprecated=True)
        parents_map = self.mitre.get_all_parent_techniques_of_all_subtechniques()
        
        # Pre-build STIX ID to ATT&CK ID mapping
        stix_to_attack_id: Dict[str, str] = {}
        for t in techniques_raw:
            aid, _ = _get_external_ref(t)
            if aid:
                stix_to_attack_id[t.id] = aid

        results = []
        for t in techniques_raw:
            attack_id, url = _get_external_ref(t)
            if not attack_id:
                continue

            is_sub = bool(getattr(t, "x_mitre_is_subtechnique", False))
            parent_attack_id = None
            if is_sub and t.id in parents_map and parents_map[t.id]:
                parent_obj = parents_map[t.id][0]["object"]
                parent_aid, _ = _get_external_ref(parent_obj)
                parent_attack_id = parent_aid

            tactics = []
            kill_chain = getattr(t, "kill_chain_phases", [])
            for kc in kill_chain:
                if getattr(kc, "kill_chain_name", "") == "mitre-attack":
                    tactics.append(getattr(kc, "phase_name", ""))

            platforms = list(getattr(t, "x_mitre_platforms", []) or [])
            data_sources = list(getattr(t, "x_mitre_data_sources", []) or [])
            detection = getattr(t, "x_mitre_detection", None)

            results.append(
                TechniqueItem(
                    stix_id=t.id,
                    attack_id=attack_id,
                    name=t.name,
                    description=getattr(t, "description", "") or "",
                    is_subtechnique=is_sub,
                    parent_attack_id=parent_attack_id,
                    tactics=tactics,
                    platforms=platforms,
                    data_sources=data_sources,
                    detection=detection,
                    url=url,
                )
            )

        return results, stix_to_attack_id

    def extract_mitigations(self) -> Tuple[List[MitigationItem], Dict[str, str]]:
        raw_mits = self.mitre.get_mitigations(remove_revoked_deprecated=True)
        results = []
        stix_to_aid: Dict[str, str] = {}
        for m in raw_mits:
            aid, url = _get_external_ref(m)
            if not aid:
                continue
            stix_to_aid[m.id] = aid
            results.append(
                MitigationItem(
                    stix_id=m.id,
                    attack_id=aid,
                    name=m.name,
                    description=getattr(m, "description", "") or "",
                    url=url,
                )
            )
        return results, stix_to_aid

    def extract_groups(self) -> Tuple[List[GroupItem], Dict[str, str]]:
        raw_groups = self.mitre.get_groups(remove_revoked_deprecated=True)
        results = []
        stix_to_aid: Dict[str, str] = {}
        for g in raw_groups:
            aid, url = _get_external_ref(g)
            if not aid:
                continue
            stix_to_aid[g.id] = aid
            aliases = list(getattr(g, "aliases", []) or [])
            results.append(
                GroupItem(
                    stix_id=g.id,
                    attack_id=aid,
                    name=g.name,
                    aliases=aliases,
                    description=getattr(g, "description", "") or "",
                    url=url,
                )
            )
        return results, stix_to_aid

    def extract_software(self) -> Tuple[List[SoftwareItem], Dict[str, str]]:
        raw_sw = self.mitre.get_software(remove_revoked_deprecated=True)
        results = []
        stix_to_aid: Dict[str, str] = {}
        for s in raw_sw:
            aid, url = _get_external_ref(s)
            if not aid:
                continue
            stix_to_aid[s.id] = aid
            aliases = list(getattr(s, "x_mitre_aliases", []) or [])
            platforms = list(getattr(s, "x_mitre_platforms", []) or [])
            results.append(
                SoftwareItem(
                    stix_id=s.id,
                    attack_id=aid,
                    name=s.name,
                    type=getattr(s, "type", "software"),
                    aliases=aliases,
                    platforms=platforms,
                    description=getattr(s, "description", "") or "",
                    url=url,
                )
            )
        return results, stix_to_aid

    def extract_relationships(
        self,
        tech_stix_to_aid: Dict[str, str],
        mit_stix_to_aid: Dict[str, str],
        grp_stix_to_aid: Dict[str, str],
        sw_stix_to_aid: Dict[str, str],
    ) -> Dict[str, List[Tuple[str, str, str]]]:
        """
        Extracts resolved relationships:
        - technique_mitigations: (technique_attack_id, mitigation_attack_id, description)
        - group_techniques: (group_attack_id, technique_attack_id, description)
        - software_techniques: (software_attack_id, technique_attack_id, description)
        """
        print("[MitreExtractor] Resolving STIX relationship matrices...")
        
        # 1. Mitigations -> Techniques
        tech_mits: List[Tuple[str, str, str]] = []
        mits_map = self.mitre.get_all_mitigations_mitigating_all_techniques()
        for tech_stix, mit_entries in mits_map.items():
            tech_aid = tech_stix_to_aid.get(tech_stix)
            if not tech_aid:
                continue
            for entry in mit_entries:
                mit_stix = entry["object"].id
                mit_aid = mit_stix_to_aid.get(mit_stix)
                if mit_aid:
                    desc = entry.get("relationship", {}).get("description", "") or ""
                    tech_mits.append((tech_aid, mit_aid, desc))

        # 2. Groups -> Techniques
        grp_techs: List[Tuple[str, str, str]] = []
        grp_map = self.mitre.get_all_techniques_used_by_all_groups()
        for grp_stix, tech_entries in grp_map.items():
            grp_aid = grp_stix_to_aid.get(grp_stix)
            if not grp_aid:
                continue
            for entry in tech_entries:
                tech_stix = entry["object"].id
                tech_aid = tech_stix_to_aid.get(tech_stix)
                if tech_aid:
                    desc = entry.get("relationship", {}).get("description", "") or ""
                    grp_techs.append((grp_aid, tech_aid, desc))

        # 3. Software -> Techniques
        sw_techs: List[Tuple[str, str, str]] = []
        sw_map = self.mitre.get_all_techniques_used_by_all_software()
        for sw_stix, tech_entries in sw_map.items():
            sw_aid = sw_stix_to_aid.get(sw_stix)
            if not sw_aid:
                continue
            for entry in tech_entries:
                tech_stix = entry["object"].id
                tech_aid = tech_stix_to_aid.get(tech_stix)
                if tech_aid:
                    desc = entry.get("relationship", {}).get("description", "") or ""
                    sw_techs.append((sw_aid, tech_aid, desc))

        # 4. Groups -> Software (Malware & Tools)
        grp_sw: List[Tuple[str, str, str]] = []
        grp_sw_map = self.mitre.get_all_software_used_by_all_groups()
        for grp_stix, sw_entries in grp_sw_map.items():
            grp_aid = grp_stix_to_aid.get(grp_stix)
            if not grp_aid:
                continue
            for entry in sw_entries:
                sw_stix = entry["object"].id
                sw_aid = sw_stix_to_aid.get(sw_stix)
                if sw_aid:
                    desc = entry.get("relationship", {}).get("description", "") or ""
                    grp_sw.append((grp_aid, sw_aid, desc))

        return {
            "technique_mitigations": tech_mits,
            "group_techniques": grp_techs,
            "software_techniques": sw_techs,
            "group_software": grp_sw,
        }
