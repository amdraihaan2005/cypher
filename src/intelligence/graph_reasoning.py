import re
import os
import json
from typing import List, Dict, Any, Optional
from collections import defaultdict

from src.mitre.db import MitreRepository
from src.mitre.schema import TechniqueItem, TechniqueDetail, MitigationItem, GroupItem, SoftwareItem
from src.search.hybrid import HybridSearchEngine
from src.intelligence.llm import get_openai_client
from src.intelligence.schema import (
    AttributedGroup,
    IdentifiedSoftware,
    PrioritizedMitigation,
    ThreatAnalysisReport,
)


# Module-level constant: read once at import time
DEFAULT_AI_MODEL = os.getenv("OPENAI_MODEL", "openai/gpt-oss-120b")


class GraphReasoningEngine:
    """
    Threat Intelligence Graph Reasoning Engine with AI-First Orchestration.
    The AI model logically analyzes and understands the user's prompt, decides
    what should and should not be in the response, and grounds all assertions
    in the verified MITRE ATT&CK knowledge graph.
    """

    def __init__(
        self,
        repo: Optional[MitreRepository] = None,
        search_engine: Optional[HybridSearchEngine] = None,
    ):
        self.repo = repo or MitreRepository()
        self.search_engine = search_engine or HybridSearchEngine(repo=self.repo)

    def close(self):
        self.search_engine.close()

    def analyze_narrative(
        self,
        query: str,
        max_techniques: int = 5,
        k: int = 60,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatAnalysisReport:
        """
        Unified RAG pipeline. Every query follows the same path:
        Search → Enrich → LLM → Response.
        The LLM adapts its response based on context (empty = conversational,
        rich = structured analysis, history = follow-up answer).
        """
        ai_answer: Optional[str] = None
        ai_model: Optional[str] = DEFAULT_AI_MODEL
        llm_client = get_openai_client()

        # ── Step 1: RETRIEVE — RRF hybrid search with multi-entity resolution ──
        explicit_techs = re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', query.upper())
        explicit_mits = re.findall(r'\b(M\d{4})\b', query.upper())
        explicit_grps = re.findall(r'\b(G\d{4})\b', query.upper())
        explicit_soft = re.findall(r'\b(S\d{4})\b', query.upper())

        # If history exists, extract prior entity IDs if query didn't specify them
        if history:
            last_turns_text = " ".join(
                h.get("content", "") for h in history[-2:] if isinstance(h.get("content"), str)
            ).upper()
            if not explicit_techs:
                explicit_techs = re.findall(r'\b(T\d{4}(?:\.\d{3})?)\b', last_turns_text)
            if not explicit_mits:
                explicit_mits = re.findall(r'\b(M\d{4})\b', last_turns_text)
            if not explicit_grps:
                explicit_grps = re.findall(r'\b(G\d{4})\b', last_turns_text)
            if not explicit_soft:
                explicit_soft = re.findall(r'\b(S\d{4})\b', last_turns_text)

        candidate_tech_ids: List[str] = list(dict.fromkeys(explicit_techs))

        # Direct mitigations from explicit M-IDs
        direct_mitigations: List[PrioritizedMitigation] = []
        for mid in explicit_mits:
            m_detail = self.repo.get_mitigation(mid)
            if m_detail:
                mit_tech_ids = [t.attack_id for t in getattr(m_detail, "techniques", [])]
                direct_mitigations.append(
                    PrioritizedMitigation(
                        mitigation=m_detail.mitigation,
                        mitigated_techniques=mit_tech_ids,
                        mitigation_count=len(mit_tech_ids),
                        coverage_percentage=0.0,
                    )
                )
                for tid in mit_tech_ids:
                    if tid not in candidate_tech_ids:
                        candidate_tech_ids.append(tid)

        # Context-augmented search for short follow-ups
        search_q = query
        if history and len(query.split()) < 8:
            last_user_queries = [
                h.get("content", "") for h in history if h.get("role") == "user" and isinstance(h.get("content"), str)
            ]
            if last_user_queries:
                search_q = f"{last_user_queries[-1]} {query}"

        rrf_hits = self.search_engine.search(
            query=search_q,
            entity_type="technique",
            limit=max_techniques,
            hydrate=False,
            k=k,
        )
        for eid, _etype, _score in rrf_hits:
            if eid not in candidate_tech_ids:
                candidate_tech_ids.append(eid)

        # Fetch verified technique details from database
        techniques: List[TechniqueItem] = []
        technique_details: List[TechniqueDetail] = []
        for tid in candidate_tech_ids[:max_techniques]:
            t_detail = self.repo.get_technique(tid)
            if t_detail:
                techniques.append(t_detail.technique)
                technique_details.append(t_detail)

        # ── Step 2: ENRICH — Graph lookups for relationships ──
        prioritized_mitigations: List[PrioritizedMitigation] = list(direct_mitigations)
        attributed_groups: List[AttributedGroup] = []
        identified_software: List[IdentifiedSoftware] = []

        if techniques:
            tech_ids = [t.attack_id for t in techniques]
            total_techs = len(tech_ids)
            placeholders = ",".join(["?"] * total_techs)

            # Mitigations
            mit_cursor = self.repo.conn.execute(
                f"""
                SELECT mitigation_attack_id, technique_attack_id
                FROM technique_mitigations
                WHERE technique_attack_id IN ({placeholders})
                """,
                tuple(tech_ids),
            )
            mit_matches: Dict[str, List[str]] = defaultdict(list)
            for r in mit_cursor.fetchall():
                mit_matches[r["mitigation_attack_id"]].append(r["technique_attack_id"])

            seen_mids = {m.mitigation.attack_id for m in direct_mitigations}
            for dm in direct_mitigations:
                overlap = [tid for tid in dm.mitigated_techniques if tid in tech_ids]
                dm.coverage_percentage = round((len(overlap) / total_techs) * 100.0, 1) if total_techs > 0 else 0.0

            for mit_id, covered_t in mit_matches.items():
                if mit_id not in seen_mids:
                    m_detail = self.repo.get_mitigation(mit_id)
                    if not m_detail:
                        continue
                    unique_covered = sorted(list(set(covered_t)))
                    cov_pct = round((len(unique_covered) / total_techs) * 100.0, 1) if total_techs > 0 else 0.0
                    prioritized_mitigations.append(
                        PrioritizedMitigation(
                            mitigation=m_detail.mitigation,
                            mitigated_techniques=unique_covered,
                            mitigation_count=len(unique_covered),
                            coverage_percentage=cov_pct,
                        )
                    )
                    seen_mids.add(mit_id)
            prioritized_mitigations.sort(key=lambda m: (m.mitigation_count, m.coverage_percentage), reverse=True)

            # Threat Groups
            grp_cursor = self.repo.conn.execute(
                f"""
                SELECT group_attack_id, technique_attack_id
                FROM group_techniques
                WHERE technique_attack_id IN ({placeholders})
                """,
                tuple(tech_ids),
            )
            grp_matches = defaultdict(list)
            for r in grp_cursor.fetchall():
                grp_matches[r["group_attack_id"]].append(r["technique_attack_id"])

            for gid, matched_t in sorted(grp_matches.items(), key=lambda x: len(x[1]), reverse=True):
                g_detail = self.repo.get_group(gid)
                if g_detail:
                    attributed_groups.append(
                        AttributedGroup(
                            group=g_detail.group,
                            matched_techniques=list(set(matched_t)),
                            overlap_count=len(set(matched_t)),
                            overlap_ratio=round(len(set(matched_t)) / total_techs, 2),
                            software_used=[s.name for s in getattr(g_detail, "software", [])],
                        )
                    )

            # Software / Tools
            sw_cursor = self.repo.conn.execute(
                f"""
                SELECT software_attack_id, technique_attack_id
                FROM software_techniques
                WHERE technique_attack_id IN ({placeholders})
                """,
                tuple(tech_ids),
            )
            sw_matches = defaultdict(list)
            for r in sw_cursor.fetchall():
                sw_matches[r["software_attack_id"]].append(r["technique_attack_id"])

            for sid, matched_t in sorted(sw_matches.items(), key=lambda x: len(x[1]), reverse=True):
                s_detail = self.repo.get_software(sid)
                if s_detail:
                    identified_software.append(
                        IdentifiedSoftware(
                            software=s_detail.software,
                            matched_techniques=list(set(matched_t)),
                            match_count=len(set(matched_t)),
                            associated_groups=[g.name for g in getattr(s_detail, "groups", [])],
                        )
                    )

        # ── Step 3: COMPILE — Build MITRE context string for the LLM ──
        context_blocks = []
        for td in technique_details:
            t = td.technique
            t_block = f"### TECHNIQUE: {t.attack_id} - {t.name}\n"
            t_block += f"Tactics: {', '.join(t.tactics) if t.tactics else 'Unspecified'}\n"
            t_block += f"Platforms: {', '.join(t.platforms) if t.platforms else 'Unspecified'}\n"
            desc = (t.description or "")[:700]
            t_block += f"Description: {desc}\n"
            if t.data_sources:
                t_block += f"Data Sources: {', '.join(t.data_sources[:4])}\n"
            if t.detection:
                t_block += f"Detection Guidance: {t.detection[:300]}\n"
            context_blocks.append(t_block)

        if prioritized_mitigations:
            mit_lines = [
                f"- {m.mitigation.attack_id} ({m.mitigation.name}): {m.mitigation.description[:450]}"
                for m in prioritized_mitigations[:4]
            ]
            context_blocks.append("### DEFENSIVE MITIGATIONS (FROM MITRE ATT&CK):\n" + "\n".join(mit_lines))

        if attributed_groups:
            grp_lines = [
                f"- {g.group.attack_id} ({g.group.name}): {g.group.description[:350]}"
                for g in attributed_groups[:3]
            ]
            context_blocks.append("### THREAT ACTOR GROUPS (FROM MITRE ATT&CK):\n" + "\n".join(grp_lines))

        if identified_software:
            sw_lines = [
                f"- {s.software.attack_id} ({s.software.name}, {s.software.type}): {s.software.description[:300]}"
                for s in identified_software[:3]
            ]
            context_blocks.append("### SOFTWARE & TOOLS (FROM MITRE ATT&CK):\n" + "\n".join(sw_lines))

        mitre_context = "\n\n".join(context_blocks)

        # ── Step 4: GENERATE — Single unified LLM call ──
        if llm_client:
            try:
                system_prompt = (
                    "You are Cypher AI, an authoritative cybersecurity intelligence engine "
                    "grounded exclusively in the MITRE ATT&CK enterprise framework.\n\n"
                    "You will receive:\n"
                    "- A user query (could be anything: a greeting, a technical question, an incident narrative, or a follow-up doubt)\n"
                    "- Conversation history (if this is a continuing thread)\n"
                    "- Retrieved MITRE ATT&CK context (if relevant data was found via hybrid search + RRF)\n\n"
                    "RESPONSE RULES:\n"
                    "1. CONVERSATION CONTINUITY (THREAD SCOPE):\n"
                    "   - If conversation history is present, you are in an ONGOING dialogue within this specific thread. NEVER re-introduce yourself, never say 'I am here to help...', and never reset the conversation persona.\n"
                    "   - Interpret short follow-ups (e.g., 'why', 'how', 'explain more', 'what does that mean', 'why is that') directly in the context of the preceding messages in this thread.\n"
                    "   - If the user asks 'why', explain the reasoning or technical justification behind the prior response or findings in this thread.\n"
                    "   - Answer conversationally, concisely, and directly. Do NOT repeat a full 5-section analysis for follow-ups unless explicitly requested.\n\n"
                    "2. MITRE GROUNDING & DATA INTEGRITY:\n"
                    "   - If retrieved MITRE context is provided, base all technical assertions strictly on that data. Do not hallucinate or fabricate information.\n"
                    "   - If NO MITRE context is provided and there is NO history (first message of a new thread), introduce yourself as Cypher AI and explain what you can help with.\n"
                    "   - If NO MITRE context is provided but history IS present, continue the discussion using the conversational context already established.\n\n"
                    "3. NEW THREAT SCENARIOS (INITIAL ANALYSIS):\n"
                    "   - For fresh incident narratives or technique queries with rich context (and no follow-up history), organize into:\n"
                    "     ### 1. Tactic Stage & Operational Objective\n"
                    "     ### 2. Mapped MITRE Techniques & Sub-Techniques\n"
                    "     ### 3. Adversary Procedures & Threat Arsenal\n"
                    "     ### 4. Telemetry & Detection Data Sources\n"
                    "     ### 5. Prioritized Defensive Mitigations Matrix\n\n"
                    "4. MITRE FORMATTING:\n"
                    "   - Always use exact MITRE IDs (T1003.001, G0016, S0005, M1025) and clean markdown bullet points.\n"
                    "   - Never fabricate MITRE IDs, technique names, or group attributions not present in the provided context or thread history."
                )

                messages = [{"role": "system", "content": system_prompt}]

                # Append conversation history if present (capped to prevent TPM overflow)
                for h in (history or [])[-6:]:
                    role = h.get("role", "user")
                    content = (h.get("content") or "").strip()
                    if content:
                        truncated = content if len(content) <= 600 else content[:600] + "..."
                        messages.append({"role": role, "content": truncated})

                # Build the user message with context
                user_content = query
                if mitre_context:
                    user_content += (
                        f"\n\n[RETRIEVED MITRE ATT&CK CONTEXT (VIA HYBRID SEARCH + RRF)]\n"
                        f"{mitre_context}"
                    )
                messages.append({"role": "user", "content": user_content})

                res = llm_client.chat.completions.create(
                    model=ai_model,
                    messages=messages,
                    temperature=0.1,
                    max_tokens=1200,
                )
                ai_answer = res.choices[0].message.content or ""
            except Exception as e:
                err_str = str(e).lower()
                print(f"[GraphReasoningEngine] AI generation issue: {e}")
                if any(kw in err_str for kw in ["rate_limit", "tpm", "413", "429", "too large", "quota"]):
                    ai_answer = (
                        "**Notice:** The AI analysis service is currently operating at maximum capacity. "
                        "All verified MITRE ATT&CK graph intelligence, technique mappings, and defensive mitigations are available below. Please retry your query in a few moments."
                    )
                elif any(kw in err_str for kw in ["auth", "api_key", "unauthorized", "401"]):
                    ai_answer = (
                        "**Notice:** AI synthesis service is temporarily unavailable. "
                        "Verified MITRE ATT&CK knowledge graph intelligence and defensive matrix remain fully accessible below."
                    )
                else:
                    ai_answer = (
                        "**Notice:** AI synthesis is temporarily unavailable. "
                        "All verified MITRE ATT&CK graph intelligence, threat actors, and prioritized mitigations are fully displayed below."
                    )

        # ── Step 5: ASSEMBLE — Build and return the report ──
        tactics_set = {tac for t in techniques for tac in (t.tactics or [])}
        platforms_set = {plat for t in techniques for plat in (t.platforms or [])}
        data_sources_set = {ds for t in techniques for ds in (t.data_sources or [])}

        chain_summary = {}
        if techniques:
            chain_summary = {
                "total_techniques_identified": len(techniques),
                "tactics_covered": sorted(list(tactics_set)),
                "platforms_affected": sorted(list(platforms_set)),
                "most_likely_actor": attributed_groups[0].group.name if attributed_groups else "Unknown",
                "top_defensive_priority": prioritized_mitigations[0].mitigation.name if prioritized_mitigations else "General Hardening",
            }

        return ThreatAnalysisReport(
            query=query,
            identified_techniques=techniques[:4],
            tactics_involved=sorted(list(tactics_set)),
            affected_platforms=sorted(list(platforms_set)),
            attributed_groups=attributed_groups[:3],
            identified_software=identified_software[:4],
            prioritized_mitigations=prioritized_mitigations[:4],
            detection_data_sources=sorted(list(data_sources_set)),
            attack_chain_summary=chain_summary,
            ai_answer=ai_answer,
            ai_model=ai_model,
        )

