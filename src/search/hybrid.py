import asyncio
from typing import List, Dict, Any, Optional, Union, Tuple, Set
from pydantic import BaseModel, ConfigDict

from src.mitre.db import MitreRepository
from src.mitre.schema import (
    TechniqueDetail,
    TacticDetail,
    MitigationDetail,
    GroupDetail,
    SoftwareDetail,
)
from src.search.sparse import SparseSearchEngine
from src.search.dense import DenseSearchEngine
from src.search.rrf import reciprocal_rank_fusion

ALLOWED_ENTITY_TYPES: Set[str] = {"technique", "group", "software", "mitigation", "tactic"}
MIN_CANDIDATE_POOL_DEPTH: int = 60


def _min_max_scale(scores: Dict[Tuple[str, str], float]) -> Dict[Tuple[str, str], float]:
    if not scores:
        return {}
    vals = list(scores.values())
    min_v, max_v = min(vals), max(vals)
    if max_v <= min_v:
        return {k: 1.0 for k in scores}
    return {k: (v - min_v) / (max_v - min_v) for k, v in scores.items()}


class ScoredEntity(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    entity_id: str
    entity_type: str  # 'technique', 'tactic', 'mitigation', 'group', 'software'
    name: str
    score: float
    dense_score: Optional[float] = None
    sparse_score: Optional[float] = None
    detail: Optional[Union[TechniqueDetail, TacticDetail, MitigationDetail, GroupDetail, SoftwareDetail, Dict[str, Any]]] = None


class HybridSearchEngine:
    def __init__(
        self,
        sparse_engine: Optional[SparseSearchEngine] = None,
        dense_engine: Optional[DenseSearchEngine] = None,
        repo: Optional[MitreRepository] = None,
    ):
        self._owns_repo = repo is None
        self._owns_sparse = sparse_engine is None

        self.repo = repo or MitreRepository()
        self.sparse = sparse_engine or SparseSearchEngine(conn=self.repo.conn)
        self.dense = dense_engine or DenseSearchEngine()

    def __enter__(self) -> "HybridSearchEngine":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        """Safely closes owned connections without destroying externally injected dependencies."""
        if self._owns_sparse:
            self.sparse.close()
        if self._owns_repo:
            self.repo.close()


    def _batch_hydrate(
        self, candidates: List[Dict[str, Any]]
    ) -> Dict[Tuple[str, str], Tuple[str, Any]]:
        by_type: Dict[str, Set[str]] = {}
        for c in candidates:
            clean_type = c["entity_type"].lower().strip()
            if clean_type not in ALLOWED_ENTITY_TYPES:
                raise ValueError(
                    f"Unrecognized entity_type: '{c['entity_type']}' for candidate '{c['entity_id']}'. "
                    f"Expected one of: {sorted(list(ALLOWED_ENTITY_TYPES))}"
                )
            by_type.setdefault(clean_type, set()).add(c["entity_id"].strip().upper())

        hydrated: Dict[Tuple[str, str], Tuple[str, Any]] = {}

        for etype, ids in by_type.items():
            if not ids:
                continue
            placeholders = ",".join(["?"] * len(ids))
            id_tuple = tuple(ids)

            if etype == "technique":
                cursor = self.repo.conn.execute(
                    f"SELECT * FROM techniques WHERE attack_id IN ({placeholders})",
                    id_tuple,
                )
                for r in cursor.fetchall():
                    tech = self.repo._row_to_technique(r)
                    detail = TechniqueDetail(
                        technique=tech,
                        subtechniques=[],
                        mitigations=[],
                        groups=[],
                        software=[],
                    )
                    hydrated[(r["attack_id"].upper(), "technique")] = (tech.name, detail)

            elif etype == "group":
                cursor = self.repo.conn.execute(
                    f"SELECT * FROM groups WHERE attack_id IN ({placeholders})",
                    id_tuple,
                )
                for r in cursor.fetchall():
                    grp = self.repo._row_to_group(r)
                    detail = GroupDetail(group=grp, techniques=[], software=[])
                    hydrated[(r["attack_id"].upper(), "group")] = (grp.name, detail)

            elif etype == "software":
                cursor = self.repo.conn.execute(
                    f"SELECT * FROM software WHERE attack_id IN ({placeholders})",
                    id_tuple,
                )
                for r in cursor.fetchall():
                    sw = self.repo._row_to_software(r)
                    detail = SoftwareDetail(software=sw, techniques=[], groups=[])
                    hydrated[(r["attack_id"].upper(), "software")] = (sw.name, detail)

            elif etype == "mitigation":
                cursor = self.repo.conn.execute(
                    f"SELECT * FROM mitigations WHERE attack_id IN ({placeholders})",
                    id_tuple,
                )
                for r in cursor.fetchall():
                    mit = self.repo._row_to_mitigation(r)
                    detail = MitigationDetail(mitigation=mit, techniques=[])
                    hydrated[(r["attack_id"].upper(), "mitigation")] = (mit.name, detail)

            elif etype == "tactic":
                cursor = self.repo.conn.execute(
                    f"SELECT * FROM tactics WHERE attack_id IN ({placeholders})",
                    id_tuple,
                )
                for r in cursor.fetchall():
                    tac = self.repo._row_to_tactic(r)
                    detail = TacticDetail(tactic=tac, techniques=[])
                    hydrated[(r["attack_id"].upper(), "tactic")] = (tac.name, detail)

        return hydrated

    def search(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        mode: str = "rrf",
        hydrate: bool = True,
        k: int = 60,
        min_dense_score: Optional[float] = None,
        alpha: float = 0.6,
        rrf_weights: Optional[Dict[str, float]] = None,
    ) -> Union[List[ScoredEntity], List[Tuple[str, str, float]]]:
    
        if not query.strip():
            return []

        clean_mode = mode.lower().strip()
        limit = max(1, limit)
        alpha = max(0.0, min(1.0, alpha))
        k = max(1, k)
        candidates: List[Dict[str, Any]] = []
        deep_pool = max(limit * 3, MIN_CANDIDATE_POOL_DEPTH)

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
            dense_threshold = min_dense_score if min_dense_score is not None else 0.0
            dense_hits = self.dense.search(query, entity_type=entity_type, limit=limit, min_score=dense_threshold)
            for eid, etype, d_score in dense_hits:
                candidates.append({
                    "entity_id": eid,
                    "entity_type": etype,
                    "score": d_score,
                    "dense_score": d_score,
                    "sparse_score": None,
                })

        elif clean_mode in ("hybrid", "linear"):
            # Deep retrieval to ensure both algorithms explore sufficient candidate overlap
            dense_hits_raw = self.dense.search(query, entity_type=entity_type, limit=deep_pool)
            sparse_hits_raw = self.sparse.search(query, entity_type=entity_type, limit=deep_pool)

            dense_map = {(eid, etype): s for eid, etype, s in dense_hits_raw}
            sparse_map = {(eid, etype): s for eid, etype, s in sparse_hits_raw}

            # Normalize both distributions to [0.0, 1.0] before applying linear weights
            norm_dense = _min_max_scale(dense_map)
            norm_sparse = _min_max_scale(sparse_map)

            all_keys = set(dense_map.keys()) | set(sparse_map.keys())
            for eid, etype in all_keys:
                d_norm = norm_dense.get((eid, etype), 0.0)
                s_norm = norm_sparse.get((eid, etype), 0.0)
                final_score = (alpha * d_norm) + ((1.0 - alpha) * s_norm)
                candidates.append({
                    "entity_id": eid,
                    "entity_type": etype,
                    "score": round(final_score, 4),
                    "dense_score": round(dense_map.get((eid, etype), 0.0), 4),
                    "sparse_score": round(sparse_map.get((eid, etype), 0.0), 4),
                })
            candidates.sort(key=lambda x: x["score"], reverse=True)
            candidates = candidates[:limit]

        else:  # default: "rrf"
            # Deep retrieval: consensus ranking requires a broad pool of candidates
            dense_threshold = min_dense_score if min_dense_score is not None else 0.55
            dense_hits = self.dense.search(
                query, entity_type=entity_type, limit=deep_pool, min_score=dense_threshold
            )
            sparse_hits = self.sparse.search(
                query, entity_type=entity_type, limit=deep_pool
            )

            if dense_hits or sparse_hits:
                dense_list = [((eid, etype), score) for eid, etype, score in dense_hits]
                sparse_list = [((eid, etype), score) for eid, etype, score in sparse_hits]

                dense_score_map = {(eid, etype): score for eid, etype, score in dense_hits}
                sparse_score_map = {(eid, etype): score for eid, etype, score in sparse_hits}

                ranked_lists = [
                    ("dense", dense_list),
                    ("sparse", sparse_list),
                ]

                fused = reciprocal_rank_fusion(ranked_lists, k=k, weights=rrf_weights)
                for (eid, etype), rrf_score, _ranks in fused[:limit]:
                    candidates.append({
                        "entity_id": eid,
                        "entity_type": etype,
                        "score": round(rrf_score, 6),
                        "dense_score": dense_score_map.get((eid, etype)),
                        "sparse_score": sparse_score_map.get((eid, etype)),
                    })

        # Early return for lightweight ID tuples (skips SQLite entity hydration entirely)
        if not hydrate:
            return [(c["entity_id"], c["entity_type"], c["score"]) for c in candidates]

        # Batch hydration: executes grouped batch queries (max 5 queries) instead of an N+1 loop
        hydrated_map = self._batch_hydrate(candidates)

        results: List[ScoredEntity] = []
        for c in candidates:
            key = (c["entity_id"].strip().upper(), c["entity_type"].lower().strip())
            name, detail = hydrated_map.get(key, (c["entity_id"], None))
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

    async def search_async(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        mode: str = "rrf",
        hydrate: bool = True,
        k: int = 60,
        min_dense_score: Optional[float] = None,
        alpha: float = 0.6,
        rrf_weights: Optional[Dict[str, float]] = None,
    ) -> Union[List[ScoredEntity], List[Tuple[str, str, float]]]:
        return await asyncio.to_thread(
            self.search,
            query,
            entity_type,
            limit,
            mode,
            hydrate,
            k,
            min_dense_score,
            alpha,
            rrf_weights,
        )

