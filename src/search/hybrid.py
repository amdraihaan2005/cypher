from typing import List, Dict, Any, Optional, Union, Tuple
from pydantic import BaseModel, Field

from src.mitre.db import MitreRepository
from src.mitre.schema import (
    TechniqueItem,
    TacticItem,
    MitigationItem,
    GroupItem,
    SoftwareItem,
    TechniqueDetail,
    TacticDetail,
    MitigationDetail,
    GroupDetail,
    SoftwareDetail,
)
from src.search.sparse import SparseSearchEngine
from src.search.dense import DenseSearchEngine


class ScoredEntity(BaseModel):
    entity_id: str
    entity_type: str  # 'technique', 'tactic', 'mitigation', 'group', 'software'
    name: str
    score: float
    dense_score: Optional[float] = None
    sparse_score: Optional[float] = None
    detail: Optional[Union[TechniqueDetail, TacticDetail, MitigationDetail, GroupDetail, SoftwareDetail, Dict[str, Any]]] = None


class HybridSearchEngine:
    """
    Coordinates Dense and Sparse search across ALL MITRE ATT&CK entities:
    Tactics, Techniques, Mitigations, Adversary Groups, and Software/Malware.
    """

    def __init__(
        self,
        sparse_engine: Optional[SparseSearchEngine] = None,
        dense_engine: Optional[DenseSearchEngine] = None,
        repo: Optional[MitreRepository] = None,
    ):
        self.repo = repo or MitreRepository()
        # Share the repo's SQLite connection with SparseSearchEngine to avoid multiple connections
        self.sparse = sparse_engine or SparseSearchEngine(conn=self.repo.conn)
        self.dense = dense_engine or DenseSearchEngine()

    def close(self):
        self.sparse.close()
        self.repo.close()

    def _hydrate_entity(self, entity_id: str, entity_type: str) -> Tuple[str, Any]:
        """Resolves full entity details and returns (name, detail_object)."""
        clean_type = entity_type.lower()
        if clean_type == "technique":
            detail = self.repo.get_technique(entity_id)
            if detail:
                return detail.technique.name, detail
        elif clean_type == "group":
            detail = self.repo.get_group(entity_id)
            if detail:
                return detail.group.name, detail
        elif clean_type == "software":
            detail = self.repo.get_software(entity_id)
            if detail:
                return detail.software.name, detail
        elif clean_type == "mitigation":
            detail = self.repo.get_mitigation(entity_id)
            if detail:
                return detail.mitigation.name, detail
        elif clean_type == "tactic":
            detail = self.repo.get_tactic(entity_id)
            if detail:
                return detail.tactic.name, detail

        return entity_id, None

    def search(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        mode: str = "rrf",
        hydrate: bool = True,
        k: int = 60,
        min_dense_score: float = 0.55,
        alpha: float = 0.6,
    ) -> Union[List[ScoredEntity], List[Tuple[str, str, float]]]:
        """
        Unified search across all MITRE ATT&CK entities (tactics, techniques, mitigations, groups, software).

        Args:
            query: The search term, ID, keyword, or natural language query.
            entity_type: Optional entity filter ('technique', 'tactic', 'mitigation', 'group', 'software').
            limit: Maximum candidates to return.
            mode: Search strategy:
                - 'rrf' (default): Reciprocal Rank Fusion fusing dense and sparse channels.
                - 'dense': Pure semantic vector embedding cosine search.
                - 'sparse': Pure BM25 token keyword search via SQLite FTS5.
                - 'hybrid': Linear combination (alpha * dense + (1 - alpha) * sparse).
            hydrate: If True, fetches full entity metadata and returns List[ScoredEntity].
                     If False, returns lightweight List[Tuple[entity_id, entity_type, score]].
            k: Smoothing constant for RRF ranking (default: 60).
            min_dense_score: Minimum similarity threshold for dense matches in RRF.
            alpha: Weight for dense matches in linear hybrid mode (0.0 to 1.0).
        """
        clean_mode = mode.lower()
        candidates: List[Dict[str, Any]] = []

        if clean_mode == "sparse":
            sparse_hits = self.sparse.search(query, entity_type=entity_type, limit=limit)
            for eid, etype, s_score in sparse_hits:
                candidates.append({
                    "entity_id": eid,
                    "entity_type": etype,
                    "score": s_score,
                    "sparse_score": s_score,
                    "dense_score": None,
                })

        elif clean_mode == "dense":
            dense_hits = self.dense.search(query, entity_type=entity_type, limit=limit)
            for eid, etype, d_score in dense_hits:
                candidates.append({
                    "entity_id": eid,
                    "entity_type": etype,
                    "score": d_score,
                    "dense_score": d_score,
                    "sparse_score": None,
                })

        elif clean_mode in ("hybrid", "linear"):
            dense_hits_raw = self.dense.search(query, entity_type=entity_type, limit=limit * 2)
            sparse_hits_raw = self.sparse.search(query, entity_type=entity_type, limit=limit * 2)

            dense_map = {(eid, etype): s for eid, etype, s in dense_hits_raw}
            sparse_map = {(eid, etype): s for eid, etype, s in sparse_hits_raw}

            all_keys = set(dense_map.keys()) | set(sparse_map.keys())
            for eid, etype in all_keys:
                d_score = dense_map.get((eid, etype), 0.0)
                s_score = sparse_map.get((eid, etype), 0.0)
                final_score = (alpha * d_score) + ((1.0 - alpha) * s_score)
                candidates.append({
                    "entity_id": eid,
                    "entity_type": etype,
                    "score": round(final_score, 4),
                    "dense_score": round(d_score, 4),
                    "sparse_score": round(s_score, 4),
                })
            candidates.sort(key=lambda x: x["score"], reverse=True)
            candidates = candidates[:limit]

        else:  # default: "rrf"
            from src.search.rrf import reciprocal_rank_fusion

            dense_hits = self.dense.search(query, entity_type=entity_type, limit=limit * 3, min_score=min_dense_score)
            sparse_hits = self.sparse.search(query, entity_type=entity_type, limit=limit * 3)

            if dense_hits or sparse_hits:
                dense_list = [((eid, etype), score) for eid, etype, score in dense_hits]
                sparse_list = [((eid, etype), score) for eid, etype, score in sparse_hits]

                dense_score_map = {(eid, etype): score for eid, etype, score in dense_hits}
                sparse_score_map = {(eid, etype): score for eid, etype, score in sparse_hits}

                ranked_lists = [
                    ("dense", dense_list),
                    ("sparse", sparse_list),
                ]

                fused = reciprocal_rank_fusion(ranked_lists, k=k)
                for (eid, etype), rrf_score, _ranks in fused[:limit]:
                    candidates.append({
                        "entity_id": eid,
                        "entity_type": etype,
                        "score": round(rrf_score, 6),
                        "dense_score": dense_score_map.get((eid, etype)),
                        "sparse_score": sparse_score_map.get((eid, etype)),
                    })

        # Early return for lightweight ID tuples (skips SQLite entity hydration)
        if not hydrate:
            return [(c["entity_id"], c["entity_type"], c["score"]) for c in candidates]

        # Hydrate full entity models
        results: List[ScoredEntity] = []
        for c in candidates:
            name, detail = self._hydrate_entity(c["entity_id"], c["entity_type"])
            results.append(
                ScoredEntity(
                    entity_id=c["entity_id"],
                    entity_type=c["entity_type"],
                    name=name,
                    score=c["score"],
                    dense_score=c["dense_score"],
                    sparse_score=c["sparse_score"],
                    detail=detail,
                )
            )

        return results


