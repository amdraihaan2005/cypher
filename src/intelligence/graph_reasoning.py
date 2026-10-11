import re
import os
from typing import List, Dict, Any, Optional, Set
from dotenv import load_dotenv

load_dotenv()

from src.mitre.db import MitreRepository
from src.mitre.schema import TechniqueItem, TechniqueDetail
from src.search.hybrid import HybridSearchEngine
from openai import AsyncOpenAI
from src.intelligence.schema import (
    AttributedGroup,
    IdentifiedSoftware,
    PrioritizedMitigation,
    ThreatAnalysisReport,
)

DEFAULT_AI_MODEL = os.getenv("OPENAI_MODEL", "openai/gpt-oss-120b")

# ── Regex patterns for MITRE ATT&CK ID extraction ──
_RE_TECHNIQUE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b', re.IGNORECASE)
_RE_MITIGATION = re.compile(r'\b(M\d{4})\b', re.IGNORECASE)
_RE_GROUP = re.compile(r'\b(G\d{4})\b', re.IGNORECASE)
_RE_SOFTWARE = re.compile(r'\b(S\d{4})\b', re.IGNORECASE)

# Score bonus for explicitly-mentioned IDs so they always rank above
# marginal semantic hits, but don't completely suppress RRF results.
_EXPLICIT_ID_BONUS = 1.0


def _extract_ids(text: str) -> Dict[str, Set[str]]:
    """Extracts all MITRE ATT&CK entity IDs from a block of text."""
    if not text:
        return {
            "techniques": set(),
            "mitigations": set(),
            "groups": set(),
            "software": set(),
        }
    upper = text.upper()
    return {
        "techniques": set(_RE_TECHNIQUE.findall(upper)),
        "mitigations": set(_RE_MITIGATION.findall(upper)),
        "groups": set(_RE_GROUP.findall(upper)),
        "software": set(_RE_SOFTWARE.findall(upper)),
    }


def _build_search_query(query: str, history: Optional[List[Dict[str, Any]]]) -> str:
    """
    Constructs the search query for the hybrid retrieval layer.

    When conversation history exists, the most recent user message is always
    prepended to the current query. The embedding model's vector space handles
    semantic blending — if the current query is self-contained, prior context
    won't materially shift cosine rankings; if it's a follow-up like
    "How do I mitigate it?", the prior turn provides the missing referent.
    """
    if not history:
        return query

    prior_user_msgs = [
        h.get("content", "")
        for h in history
        if h.get("role") == "user" and isinstance(h.get("content"), str)
    ]
    if prior_user_msgs:
        return f"{prior_user_msgs[-1]} {query}"
    return query


# ── Prompt template rendering ──

def _render_technique_block(td: TechniqueDetail) -> str:
    """Renders a single technique into a structured context block for the LLM."""
    t = td.technique
    lines = [
        f"### TECHNIQUE: {t.attack_id}",
        t.name,
        f"Tactics: {', '.join(t.tactics) if t.tactics else 'Unspecified'}",
        f"Platforms: {', '.join(t.platforms) if t.platforms else 'Unspecified'}",
        f"Description: {(t.description or '')[:700]}",
    ]
    if t.data_sources:
        lines.append(f"Data Sources: {', '.join(t.data_sources[:4])}")
    if t.detection:
        lines.append(f"Detection Guidance: {t.detection[:300]}")
    return "\n".join(lines)


def _render_mitigations_block(
    mitigations: List[PrioritizedMitigation], limit: int
) -> Optional[str]:
    """Renders the mitigations section, or None if empty."""
    if not mitigations:
        return None
    items = []
    for m in mitigations[:limit]:
        desc = (m.mitigation.description or "").strip()
        desc_snippet = f": {desc[:450]}" if desc else ""
        items.append(f"- {m.mitigation.attack_id} ({m.mitigation.name}){desc_snippet}")
    return "### DEFENSIVE MITIGATIONS (FROM MITRE ATT&CK):\n" + "\n".join(items)


def _render_groups_block(
    groups: List[AttributedGroup], limit: int
) -> Optional[str]:
    """Renders the threat actors section, or None if empty."""
    if not groups:
        return None
    items = []
    for g in groups[:limit]:
        desc = (g.group.description or "").strip()
        desc_snippet = f": {desc[:350]}" if desc else ""
        items.append(f"- {g.group.attack_id} ({g.group.name}){desc_snippet}")
    return "### THREAT ACTOR GROUPS (FROM MITRE ATT&CK):\n" + "\n".join(items)


def _render_software_block(
    software: List[IdentifiedSoftware], limit: int
) -> Optional[str]:
    """Renders the software/tools section, or None if empty."""
    if not software:
        return None
    items = []
    for s in software[:limit]:
        desc = (s.software.description or "").strip()
        desc_snippet = f": {desc[:300]}" if desc else ""
        items.append(f"- {s.software.attack_id} ({s.software.name}, {s.software.type}){desc_snippet}")
    return "### SOFTWARE & TOOLS (FROM MITRE ATT&CK):\n" + "\n".join(items)


_SYSTEM_PROMPT = (
    "You are Cypher AI, an authoritative cybersecurity intelligence engine "
    "grounded exclusively in the MITRE ATT&CK enterprise framework.\n\n"
    "You will receive:\n"
    "- A user query (incident narrative, technique ID, or follow-up question)\n"
    "- Conversation history (if this is an ongoing dialogue)\n"
    "- Retrieved MITRE ATT&CK context (verified techniques, groups, software, mitigations)\n\n"
    "RESPONSE RULES:\n"
    "1. CONVERSATION CONTINUITY:\n"
    "   - If conversation history is present, you are in an ongoing dialogue. Never re-introduce yourself.\n"
    "   - Interpret short follow-ups directly in the context of preceding turns.\n"
    "2. MITRE GROUNDING:\n"
    "   - Base all technical claims strictly on the provided MITRE context. Never fabricate attack IDs or group names.\n"
    "3. THREAT ANALYSIS STRUCTURE (FOR NEW SCENARIOS):\n"
    "   - Organize into clean sections: Tactic Stage, Mapped Techniques, Adversary Procedures, Detection Guidance, and Prioritized Mitigations.\n"
    "4. FORMATTING:\n"
    "   - Always use exact MITRE IDs (e.g., T1059.001, G0016, S0005, M1025) and clean markdown."
)


class GraphReasoningEngine:
    """
    Threat Intelligence Retrieve-Enrich-Synthesize Pipeline.

    Orchestrates a 3-stage pipeline for MITRE ATT&CK threat analysis:

    1. RETRIEVE — Hybrid search (dense ONNX embeddings + sparse BM25 FTS5,
       fused via Reciprocal Rank Fusion) combined with explicit regex entity
       extraction. Candidate technique IDs are ranked by a scored priority
       merge that preserves both explicit mentions and semantic relevance.

    2. ENRICH — Relational graph joins against SQLite junction tables
       (technique_mitigations, group_techniques, software_techniques) to
       hydrate associated mitigations, threat actors, and software.
       Aggregation is performed at the SQL layer (GROUP BY / COUNT /
       GROUP_CONCAT) — not in Python loops.

    3. SYNTHESIZE — Async LLM generation grounded strictly on the retrieved
       and enriched MITRE context via GroqCloud.

    Note: This is NOT multi-hop graph traversal. Step 2 performs 1-hop
    relational joins (WHERE technique_id IN ...), which is efficient and
    deterministic but should not be confused with graph reasoning algorithms
    like BFS, DFS, or PageRank.

    Concurrency: analyze_narrative is async. The LLM network call is awaited,
    releasing the event loop to serve other requests while the LLM responds.
    SQLite I/O is blocking but fast (sub-millisecond local reads); FastAPI
    runs sync DB calls on its threadpool executor, while this method itself
    does not block the event loop during the expensive LLM round-trip.
    """

    def __init__(
        self,
        repo: Optional[MitreRepository] = None,
        search_engine: Optional[HybridSearchEngine] = None,
        max_history_turns: int = 6,
        max_actors: int = 3,
        max_software: int = 4,
        max_mitigations: int = 4,
    ):
        self.repo = repo or MitreRepository()
        self.search_engine = search_engine or HybridSearchEngine(repo=self.repo)
        self.max_history_turns = max_history_turns
        self.max_actors = max_actors
        self.max_software = max_software
        self.max_mitigations = max_mitigations
        self._llm_client: Optional[AsyncOpenAI] = None

    def _get_llm_client(self) -> Optional[AsyncOpenAI]:
        """Returns a reused AsyncOpenAI client instance or initializes one if credentials exist."""
        if self._llm_client is not None:
            return self._llm_client

        openai_key = os.getenv("OPENAI_API_KEY")
        groq_key = os.getenv("GROQ_API_KEY")

        if openai_key:
            base_url = os.getenv("OPENAI_BASE_URL")
            self._llm_client = AsyncOpenAI(api_key=openai_key, base_url=base_url)
        elif groq_key:
            base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
            self._llm_client = AsyncOpenAI(api_key=groq_key, base_url=base_url)

        return self._llm_client

    def _resolve_model(self) -> str:
        """Resolves the default AI model based on environment configuration."""
        if os.getenv("OPENAI_MODEL"):
            return os.environ["OPENAI_MODEL"]
        if os.getenv("OPENAI_API_KEY"):
            return DEFAULT_AI_MODEL
        if os.getenv("GROQ_API_KEY"):
            return os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
        return DEFAULT_AI_MODEL

    def close(self):
        """Safely releases SQLite database, search index connections, and LLM HTTP client."""
        if self._llm_client is not None:
            try:
                import asyncio
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop and loop.is_running():
                    loop.create_task(self._llm_client.close())
                else:
                    asyncio.run(self._llm_client.close())
            except Exception:
                pass
            self._llm_client = None
        try:
            self.search_engine.close()
        except Exception:
            pass
        try:
            self.repo.close()
        except Exception:
            pass

    async def aclose(self):
        """Asynchronously releases SQLite database, search index, and closes LLM HTTP pools."""
        if self._llm_client is not None:
            try:
                await self._llm_client.close()
            except Exception:
                pass
            self._llm_client = None
        try:
            self.search_engine.close()
        except Exception:
            pass
        try:
            self.repo.close()
        except Exception:
            pass

    def __enter__(self) -> "GraphReasoningEngine":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def __aenter__(self) -> "GraphReasoningEngine":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    async def analyze_narrative(
        self,
        query: str,
        max_techniques: int = 5,
        k: int = 60,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> ThreatAnalysisReport:
        ai_answer: Optional[str] = None
        ai_model: Optional[str] = self._resolve_model()
        llm_client = self._get_llm_client()

        # ── Step 1: RETRIEVE — Scored Priority Merge ─────────────
        #
        # Extract explicit entity IDs from the current query AND from
        # history (always merged via set union, never mutually exclusive).
        current_ids = _extract_ids(query)
        if history:
            history_text = " ".join(
                h.get("content", "")
                for h in history[-2:]
                if isinstance(h.get("content"), str)
            )
            history_ids = _extract_ids(history_text)
            for key in current_ids:
                current_ids[key] |= history_ids[key]

        explicit_techs = current_ids["techniques"]
        explicit_mits = current_ids["mitigations"]
        explicit_grps = current_ids["groups"]
        explicit_soft = current_ids["software"]

        # Scored candidate pool: {technique_id: best_score}
        # Explicit regex matches get a bonus so they always outrank marginal
        # semantic hits, but DON'T suppress high-confidence RRF results.
        scored_candidates: Dict[str, float] = {}

        for tid in explicit_techs:
            scored_candidates[tid] = _EXPLICIT_ID_BONUS

        # Expand explicit mitigations → their techniques
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
                    scored_candidates.setdefault(tid, _EXPLICIT_ID_BONUS)

        # Expand explicit groups → their techniques
        for gid in explicit_grps:
            g_detail = self.repo.get_group(gid)
            if g_detail:
                for t in getattr(g_detail, "techniques", []):
                    scored_candidates.setdefault(t.attack_id, _EXPLICIT_ID_BONUS)

        # Expand explicit software → their techniques
        for sid in explicit_soft:
            s_detail = self.repo.get_software(sid)
            if s_detail:
                for t in getattr(s_detail, "techniques", []):
                    scored_candidates.setdefault(t.attack_id, _EXPLICIT_ID_BONUS)

        # Hybrid RRF semantic search — always runs, results compete on merit.
        # History is always prepended to the search vector; the embedding model
        # handles semantic blending without heuristics.
        search_q = _build_search_query(query, history)
        rrf_hits = await self.search_engine.search_async(
            query=search_q,
            entity_type="technique",
            limit=max_techniques * 3,
            hydrate=False,
            k=k,
        )
        for eid, _etype, rrf_score in rrf_hits:
            # Keep the higher score if this ID was also an explicit mention
            scored_candidates[eid] = max(scored_candidates.get(eid, 0.0), rrf_score)

        # Rank by score descending and take top-K
        ranked_ids = sorted(
            scored_candidates.keys(),
            key=lambda tid: scored_candidates[tid],
            reverse=True,
        )[:max_techniques]

        # Fetch verified technique details from database
        techniques: List[TechniqueItem] = []
        technique_details: List[TechniqueDetail] = []
        for tid in ranked_ids:
            t_detail = self.repo.get_technique(tid)
            if t_detail:
                techniques.append(t_detail.technique)
                technique_details.append(t_detail)

        # ── Step 2: ENRICH — Relational Graph Joins (SQLite) ─────
        prioritized_mitigations: List[PrioritizedMitigation] = list(direct_mitigations)
        attributed_groups: List[AttributedGroup] = []
        identified_software: List[IdentifiedSoftware] = []

        if techniques:
            tech_ids = [t.attack_id for t in techniques]
            total_techs = len(tech_ids)
            placeholders = ",".join(["?"] * total_techs)

            # Mitigations (aggregated at SQL layer)
            mit_cursor = self.repo.conn.execute(
                f"""
                SELECT mitigation_attack_id,
                       COUNT(technique_attack_id) as mit_count,
                       GROUP_CONCAT(technique_attack_id) as matched_techs
                FROM technique_mitigations
                WHERE technique_attack_id IN ({placeholders})
                GROUP BY mitigation_attack_id
                ORDER BY mit_count DESC
                """,
                tuple(tech_ids),
            )

            seen_mids = {m.mitigation.attack_id for m in direct_mitigations}
            for dm in direct_mitigations:
                overlap = [tid for tid in dm.mitigated_techniques if tid in tech_ids]
                dm.coverage_percentage = round((len(overlap) / total_techs) * 100.0, 1) if total_techs > 0 else 0.0

            for r in mit_cursor.fetchall():
                mit_id = r["mitigation_attack_id"]
                if mit_id not in seen_mids:
                    m_detail = self.repo.get_mitigation(mit_id)
                    if not m_detail:
                        continue
                    matched_list = sorted(list(set(r["matched_techs"].split(",")))) if r["matched_techs"] else []
                    cov_pct = round((len(matched_list) / total_techs) * 100.0, 1) if total_techs > 0 else 0.0
                    prioritized_mitigations.append(
                        PrioritizedMitigation(
                            mitigation=m_detail.mitigation,
                            mitigated_techniques=matched_list,
                            mitigation_count=r["mit_count"],
                            coverage_percentage=cov_pct,
                        )
                    )
                    seen_mids.add(mit_id)
            prioritized_mitigations.sort(key=lambda m: (m.mitigation_count, m.coverage_percentage), reverse=True)

            # Threat Groups (aggregated and bounded at SQL layer)
            grp_cursor = self.repo.conn.execute(
                f"""
                SELECT group_attack_id,
                       COUNT(technique_attack_id) as overlap_count,
                       GROUP_CONCAT(technique_attack_id) as matched_techs
                FROM group_techniques
                WHERE technique_attack_id IN ({placeholders})
                GROUP BY group_attack_id
                ORDER BY overlap_count DESC
                LIMIT 5
                """,
                tuple(tech_ids),
            )
            for r in grp_cursor.fetchall():
                g_detail = self.repo.get_group(r["group_attack_id"])
                if g_detail:
                    matched_list = sorted(list(set(r["matched_techs"].split(",")))) if r["matched_techs"] else []
                    attributed_groups.append(
                        AttributedGroup(
                            group=g_detail.group,
                            matched_techniques=matched_list,
                            overlap_count=r["overlap_count"],
                            overlap_ratio=round(r["overlap_count"] / total_techs, 2),
                            software_used=[s.name for s in getattr(g_detail, "software", [])],
                        )
                    )

            # Software/Tools (aggregated and bounded at SQL layer)
            sw_cursor = self.repo.conn.execute(
                f"""
                SELECT software_attack_id,
                       COUNT(technique_attack_id) as match_count,
                       GROUP_CONCAT(technique_attack_id) as matched_techs
                FROM software_techniques
                WHERE technique_attack_id IN ({placeholders})
                GROUP BY software_attack_id
                ORDER BY match_count DESC
                LIMIT 6
                """,
                tuple(tech_ids),
            )
            for r in sw_cursor.fetchall():
                s_detail = self.repo.get_software(r["software_attack_id"])
                if s_detail:
                    matched_list = sorted(list(set(r["matched_techs"].split(",")))) if r["matched_techs"] else []
                    identified_software.append(
                        IdentifiedSoftware(
                            software=s_detail.software,
                            matched_techniques=matched_list,
                            match_count=r["match_count"],
                            associated_groups=[g.name for g in getattr(s_detail, "groups", [])],
                        )
                    )

        # ── Step 3: COMPILE — Structured Context for LLM ─────────
        context_blocks = [_render_technique_block(td) for td in technique_details]

        mit_block = _render_mitigations_block(prioritized_mitigations, self.max_mitigations)
        if mit_block:
            context_blocks.append(mit_block)

        grp_block = _render_groups_block(attributed_groups, self.max_actors)
        if grp_block:
            context_blocks.append(grp_block)

        sw_block = _render_software_block(identified_software, self.max_software)
        if sw_block:
            context_blocks.append(sw_block)

        mitre_context = "\n\n".join(context_blocks)

        # ── Step 4: SYNTHESIZE — Async Grounded LLM Generation ───
        # The LLM call is awaited, releasing the event loop to serve other
        # requests concurrently while the network round-trip completes.
        # Structured JSON output is used for OpenAI; Groq does not support
        # json_schema response_format and falls back to plain markdown.
        if llm_client:
            try:
                messages: List[Dict[str, str]] = [
                    {"role": "system", "content": _SYSTEM_PROMPT}
                ]

                for h in (history or [])[-self.max_history_turns:]:
                    role = h.get("role", "user")
                    content = (h.get("content") or "").strip()
                    if content:
                        truncated = content if len(content) <= 600 else content[:600] + "..."
                        messages.append({"role": role, "content": truncated})

                user_content = query
                if mitre_context:
                    user_content += (
                        f"\n\n[RETRIEVED MITRE ATT&CK CONTEXT (VIA HYBRID SEARCH + RRF)]\n"
                        f"{mitre_context}"
                    )
                messages.append({"role": "user", "content": user_content})

                res = await llm_client.chat.completions.create(
                    model=ai_model,
                    messages=messages,
                    temperature=0.1,
                    max_tokens=1200,
                )
                ai_answer = res.choices[0].message.content or ""

            except Exception as e:
                err_str = str(e).lower()
                print(f"[GraphReasoningEngine] AI generation notice: {e}")
                if any(kw in err_str for kw in ["rate_limit", "tpm", "413", "429", "too large", "quota"]):
                    ai_answer = (
                        "**Notice:** The AI analysis service is operating at peak capacity. "
                        "All verified MITRE ATT&CK graph intelligence and prioritized mitigations are fully displayed below."
                    )
                elif any(kw in err_str for kw in ["auth", "api_key", "unauthorized", "401"]):
                    ai_answer = (
                        "**Notice:** AI synthesis service is temporarily unavailable. "
                        "Verified MITRE ATT&CK knowledge graph intelligence and defensive matrix remain fully accessible below."
                    )
                else:
                    ai_answer = (
                        "**Notice:** AI synthesis is currently unavailable. "
                        "All verified MITRE ATT&CK graph intelligence, threat actors, and prioritized mitigations are fully displayed below."
                    )

        if not ai_answer:
            if techniques:
                tech_names = ", ".join(f"**{t.name}** (`{t.attack_id}`)" for t in techniques[:3])
                ai_answer = (
                    f"### MITRE ATT&CK Threat Analysis\n\n"
                    f"Identified the following verified techniques matching your query: {tech_names}.\n\n"
                    f"Explore the identified techniques, prioritized mitigations, and attributed threat actors in the matrices below."
                )
            else:
                ai_answer = (
                    "Hello! I am **Cypher AI**, an authoritative cybersecurity intelligence engine grounded in the MITRE ATT&CK framework.\n\n"
                    "Ask any cybersecurity question, describe an observed attack or incident narrative, or query a technique ID (e.g. `T1059.001`, `T1003`)."
                )

        # ── Step 5: ASSEMBLE — Build and Return Report ───────────
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
            identified_techniques=techniques[:max_techniques],
            tactics_involved=sorted(list(tactics_set)),
            affected_platforms=sorted(list(platforms_set)),
            attributed_groups=attributed_groups[:self.max_actors],
            identified_software=identified_software[:self.max_software],
            prioritized_mitigations=prioritized_mitigations[:self.max_mitigations],
            detection_data_sources=sorted(list(data_sources_set)),
            attack_chain_summary=chain_summary,
            ai_answer=ai_answer,
            ai_model=ai_model,
        )
