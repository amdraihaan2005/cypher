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

    def search_sparse(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[ScoredEntity]:
        """Sparse token search across entities with optional entity_type filter."""
        sparse_hits = self.sparse.search(query, entity_type=entity_type, limit=limit)
        results = []
        for entity_id, e_type, score in sparse_hits:
            name, detail = self._hydrate_entity(entity_id, e_type)
            results.append(
                ScoredEntity(
                    entity_id=entity_id,
                    entity_type=e_type,
                    name=name,
                    score=score,
                    sparse_score=score,
                    detail=detail,
                )
            )
        return results

    def search_dense(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[ScoredEntity]:
        """Dense semantic vector search across entities with optional entity_type filter."""
        dense_hits = self.dense.search(query, entity_type=entity_type, limit=limit)
        results = []
        for entity_id, e_type, score in dense_hits:
            name, detail = self._hydrate_entity(entity_id, e_type)
            results.append(
                ScoredEntity(
                    entity_id=entity_id,
                    entity_type=e_type,
                    name=name,
                    score=score,
                    dense_score=score,
                    detail=detail,
                )
            )
        return results

    def search_hybrid(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        alpha: float = 0.6,
    ) -> List[ScoredEntity]:
        """
        Executes both dense and sparse searches across all MITRE entities and merges rankings.
        Score = alpha * dense_score + (1 - alpha) * sparse_score.
        """
        dense_hits_raw = self.dense.search(query, entity_type=entity_type, limit=limit * 2)
        sparse_hits_raw = self.sparse.search(query, entity_type=entity_type, limit=limit * 2)

        dense_map = {(eid, etype): score for eid, etype, score in dense_hits_raw}
        sparse_map = {(eid, etype): score for eid, etype, score in sparse_hits_raw}

        all_keys = set(dense_map.keys()) | set(sparse_map.keys())
        if not all_keys:
            return []

        combined = []
        for eid, etype in all_keys:
            d_score = dense_map.get((eid, etype), 0.0)
            s_score = sparse_map.get((eid, etype), 0.0)
            final_score = (alpha * d_score) + ((1.0 - alpha) * s_score)
            combined.append({
                "entity_id": eid,
                "entity_type": etype,
                "score": round(final_score, 4),
                "dense_score": round(d_score, 4),
                "sparse_score": round(s_score, 4),
            })

        combined.sort(key=lambda x: x["score"], reverse=True)
        top_candidates = combined[:limit]

        results = []
        for item in top_candidates:
            name, detail = self._hydrate_entity(item["entity_id"], item["entity_type"])
            results.append(
                ScoredEntity(
                    entity_id=item["entity_id"],
                    entity_type=item["entity_type"],
                    name=name,
                    score=item["score"],
                    dense_score=item["dense_score"],
                    sparse_score=item["sparse_score"],
                    detail=detail,
                )
            )

        return results

    def search_rrf(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        k: int = 60,
        min_dense_score: float = 0.55,
    ) -> List[ScoredEntity]:
        """
        Executes dense and sparse searches and fuses candidate rankings using
        Reciprocal Rank Fusion (RRF): Score = sum(1 / (k + rank)).
        Filters out low-relevance dense candidates below min_dense_score.
        """
        from src.search.rrf import reciprocal_rank_fusion

        dense_hits = self.dense.search(query, entity_type=entity_type, limit=limit * 3, min_score=min_dense_score)
        sparse_hits = self.sparse.search(query, entity_type=entity_type, limit=limit * 3)

        if not dense_hits and not sparse_hits:
            return []

        dense_list = [((eid, etype), score) for eid, etype, score in dense_hits]
        sparse_list = [((eid, etype), score) for eid, etype, score in sparse_hits]

        dense_score_map = {(eid, etype): score for eid, etype, score in dense_hits}
        sparse_score_map = {(eid, etype): score for eid, etype, score in sparse_hits}

        ranked_lists = [
            ("dense", dense_list),
            ("sparse", sparse_list),
        ]

        fused = reciprocal_rank_fusion(ranked_lists, k=k)
        top_fused = fused[:limit]

        results = []
        for (eid, etype), rrf_score, ranks in top_fused:
            name, detail = self._hydrate_entity(eid, etype)
            results.append(
                ScoredEntity(
                    entity_id=eid,
                    entity_type=etype,
                    name=name,
                    score=rrf_score,
                    dense_score=dense_score_map.get((eid, etype)),
                    sparse_score=sparse_score_map.get((eid, etype)),
                    detail=detail,
                )
            )

        return results

    def search_rrf_ids(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        k: int = 60,
        min_dense_score: float = 0.55,
    ) -> List[Tuple[str, str, float]]:
        """
        Lightweight RRF search that returns only (entity_id, entity_type, rrf_score)
        tuples without expensive entity hydration. Filters out sub-threshold dense matches.
        """
        from src.search.rrf import reciprocal_rank_fusion

        dense_hits = self.dense.search(query, entity_type=entity_type, limit=limit * 3, min_score=min_dense_score)
        sparse_hits = self.sparse.search(query, entity_type=entity_type, limit=limit * 3)

        if not dense_hits and not sparse_hits:
            return []

        dense_list = [((eid, etype), score) for eid, etype, score in dense_hits]
        sparse_list = [((eid, etype), score) for eid, etype, score in sparse_hits]

        ranked_lists = [
            ("dense", dense_list),
            ("sparse", sparse_list),
        ]

        fused = reciprocal_rank_fusion(ranked_lists, k=k)
        top_fused = fused[:limit]

        return [(eid, etype, round(rrf_score, 6)) for (eid, etype), rrf_score, _ranks in top_fused]

