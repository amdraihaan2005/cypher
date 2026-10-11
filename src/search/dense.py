import json
import asyncio
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
import numpy as np
from fastembed import TextEmbedding

from src.mitre.db import get_connection, DEFAULT_DB_PATH

DEFAULT_EMBEDDINGS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "mitre" / "embeddings.npz"
DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"


def _decode_numpy_str(val: Any) -> str:
    """Safely converts numpy bytes/str objects to clean Python strings, stripping any b' prefixes."""
    if isinstance(val, (bytes, np.bytes_)):
        return val.decode("utf-8", errors="replace")
    s = str(val)
    if (s.startswith("b'") and s.endswith("'")) or (s.startswith('b"') and s.endswith('"')):
        return s[2:-1]
    return s


def _safe_json_loads(val: Optional[str], default=None) -> Any:
    """Safely parses JSON string with fallback to default if malformed."""
    if not val:
        return default if default is not None else []
    try:
        return json.loads(val)
    except Exception:
        return default if default is not None else []


class DenseSearchEngine:
    """
    Dense semantic vector search using FastEmbed ONNX embeddings and NumPy cosine similarity.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        embeddings_path: Optional[Path] = None,
        model_name: str = DEFAULT_MODEL_NAME,
    ):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.embeddings_path = embeddings_path or DEFAULT_EMBEDDINGS_PATH
        self.model_name = model_name

        self._model: Optional[TextEmbedding] = None
        self.entity_ids: List[str] = []
        self.entity_types: List[str] = []
        self.names: List[str] = []
        self.vectors: Optional[np.ndarray] = None  # Normalized (N, D) float32 matrix
        self.type_indices: Dict[str, np.ndarray] = {}  # Precomputed O(1) type indices

        self._load_cached_embeddings()

    def close(self):
        """Releases cached embedding model and in-memory resources."""
        self._model = None

    def __enter__(self) -> "DenseSearchEngine":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    @property

    def model(self) -> TextEmbedding:
        if self._model is None:
            self._model = TextEmbedding(model_name=self.model_name)
        return self._model

    def _load_cached_embeddings(self) -> bool:
        """Loads precomputed vectors from disk without pickle risk (allow_pickle=False)."""
        if self.embeddings_path.exists():
            try:
                with np.load(str(self.embeddings_path), allow_pickle=False) as data:
                    if "entity_ids" in data and "entity_types" in data:
                        self.entity_ids = [_decode_numpy_str(x) for x in data["entity_ids"]]
                        self.entity_types = [_decode_numpy_str(x) for x in data["entity_types"]]
                        self.names = [_decode_numpy_str(x) for x in data["names"]]
                        self.vectors = np.asarray(data["vectors"], dtype=np.float32)

                        # Pre-compute integer index arrays for O(1) type filtering
                        self._build_type_indices()
                        return True
            except Exception as e:
                print(f"[DenseSearchEngine] Warning: failed to load embeddings cache: {e}")
        return False

    def _build_type_indices(self):
        """Pre-computes index arrays for each entity type to eliminate runtime string iteration."""
        type_map: Dict[str, List[int]] = {}
        for i, t in enumerate(self.entity_types):
            type_map.setdefault(t.lower(), []).append(i)
        self.type_indices = {
            t: np.array(indices, dtype=np.int32)
            for t, indices in type_map.items()
        }

    def build_index(self):
        conn = get_connection(self.db_path)
        try:
            tac_rows = conn.execute("SELECT attack_id, name, shortname, description FROM tactics ORDER BY attack_id").fetchall()
            tech_rows = conn.execute("SELECT attack_id, name, tactics_json, platforms_json, detection, description FROM techniques ORDER BY attack_id").fetchall()
            mit_rows = conn.execute("SELECT attack_id, name, description FROM mitigations ORDER BY attack_id").fetchall()
            grp_rows = conn.execute("SELECT attack_id, name, aliases_json, description FROM groups ORDER BY attack_id").fetchall()
            sw_rows = conn.execute("SELECT attack_id, name, type, aliases_json, platforms_json, description FROM software ORDER BY attack_id").fetchall()
        finally:
            conn.close()

        entity_ids = []
        entity_types = []
        names = []
        documents = []

        # 1. Tactics
        for r in tac_rows:
            try:
                entity_ids.append(r["attack_id"])
                entity_types.append("tactic")
                names.append(r["name"])
                desc = r["description"] or ""
                documents.append(f"{r['attack_id']}: {r['name']} [ATT&CK Tactic]. Goal: {r['name']}. Shortname: {r['shortname']}. {desc}")
            except Exception as e:
                print(f"[DenseSearchEngine] Warning: skipping tactic {r['attack_id']}: {e}")

        # 2. Techniques & Sub-techniques
        for r in tech_rows:
            try:
                tactics = ", ".join(_safe_json_loads(r["tactics_json"]))
                platforms = ", ".join(_safe_json_loads(r["platforms_json"]))
                detection = r["detection"] or ""
                desc = r["description"] or ""
                entity_ids.append(r["attack_id"])
                entity_types.append("technique")
                names.append(r["name"])
                documents.append(f"{r['attack_id']}: {r['name']} [ATT&CK Technique]. Tactics: {tactics}. Platforms: {platforms}. Detection: {detection}. {desc}")
            except Exception as e:
                print(f"[DenseSearchEngine] Warning: skipping technique {r['attack_id']}: {e}")

        # 3. Mitigations
        for r in mit_rows:
            try:
                entity_ids.append(r["attack_id"])
                entity_types.append("mitigation")
                names.append(r["name"])
                desc = r["description"] or ""
                documents.append(f"{r['attack_id']}: {r['name']} [Defensive Mitigation / Security Control]. {desc}")
            except Exception as e:
                print(f"[DenseSearchEngine] Warning: skipping mitigation {r['attack_id']}: {e}")

        # 4. Groups (APTs)
        for r in grp_rows:
            try:
                aliases = ", ".join(_safe_json_loads(r["aliases_json"]))
                desc = r["description"] or ""
                entity_ids.append(r["attack_id"])
                entity_types.append("group")
                names.append(r["name"])
                documents.append(f"{r['attack_id']}: {r['name']} [Adversary Threat Group / APT]. Known aliases: {aliases}. {desc}")
            except Exception as e:
                print(f"[DenseSearchEngine] Warning: skipping group {r['attack_id']}: {e}")

        # 5. Software (Malware & Tools)
        for r in sw_rows:
            try:
                aliases = ", ".join(_safe_json_loads(r["aliases_json"]))
                platforms = ", ".join(_safe_json_loads(r["platforms_json"]))
                desc = r["description"] or ""
                entity_ids.append(r["attack_id"])
                entity_types.append("software")
                names.append(r["name"])
                documents.append(f"{r['attack_id']}: {r['name']} [{r['type'].capitalize() if r['type'] else 'Software'} Tool]. Known aliases: {aliases}. Platforms: {platforms}. {desc}")
            except Exception as e:
                print(f"[DenseSearchEngine] Warning: skipping software {r['attack_id']}: {e}")

        if not documents:
            raise ValueError("[DenseSearchEngine] No valid documents to index.")

        print(f"[DenseSearchEngine] Embedding all {len(documents)} MITRE entities via {self.model_name}...")

        # Pre-allocate contiguous array to stream generator directly without RAM duplication
        embed_gen = self.model.embed(documents, batch_size=128)
        first_emb = next(embed_gen)
        dim = first_emb.shape[0]

        vectors = np.empty((len(documents), dim), dtype=np.float32)
        vectors[0] = first_emb

        for idx, emb in enumerate(embed_gen, start=1):
            vectors[idx] = emb

        # L2-normalize in place
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        vectors /= norms

        self.embeddings_path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            str(self.embeddings_path),
            entity_ids=np.array(entity_ids),
            entity_types=np.array(entity_types),
            names=np.array(names),
            vectors=vectors,
        )

        self.entity_ids = entity_ids
        self.entity_types = entity_types
        self.names = names
        self.vectors = vectors
        self._build_type_indices()
        print(f"[DenseSearchEngine] Saved {len(entity_ids)} entity embeddings to {self.embeddings_path}")

    def search(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        min_score: float = 0.0,
    ) -> List[Tuple[str, str, float]]:
        """
        Computes cosine similarity between query embedding and all precomputed entity vectors.
        Returns list of (entity_id, entity_type, similarity_score) sorted in descending order.
        """
        if self.vectors is None or len(self.entity_ids) == 0:
            if not self._load_cached_embeddings():
                raise FileNotFoundError(
                    f"[DenseSearchEngine] Embeddings cache not found at '{self.embeddings_path}'. "
                    f"Index generation must be performed offline via 'DenseSearchEngine.build_index()' before serving requests."
                )

        cleaned = query.strip()
        if not cleaned:
            return []

        limit = max(1, limit)

        # Embed query without intermediate list allocation
        query_emb = next(self.model.embed([cleaned]))
        q_vec = np.asarray(query_emb, dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm > 0:
            q_vec = q_vec / q_norm

        # Filter candidate vectors if entity_type is requested using O(1) precomputed indices
        if entity_type:
            target_type = entity_type.strip().lower()
            matching_indices = self.type_indices.get(target_type)
            if matching_indices is None or len(matching_indices) == 0:
                return []
            candidate_vectors = self.vectors[matching_indices]
            similarities = np.dot(candidate_vectors, q_vec)
        else:
            matching_indices = None
            similarities = np.dot(self.vectors, q_vec)

        # Filter candidates by min_score BEFORE partition / sorting
        if min_score > 0.0:
            valid_mask = similarities >= min_score
            if not np.any(valid_mask):
                return []
            valid_indices = np.where(valid_mask)[0]
            filtered_scores = similarities[valid_indices]
        else:
            valid_indices = np.arange(len(similarities))
            filtered_scores = similarities

        n_valid = len(valid_indices)
        top_k = min(limit, n_valid)

        if top_k >= n_valid:
            sorted_rel_idx = np.argsort(-filtered_scores)
        else:
            part = np.argpartition(-filtered_scores, top_k)[:top_k]
            sorted_rel_idx = part[np.argsort(-filtered_scores[part])]

        results = []
        for i in sorted_rel_idx:
            sub_idx = valid_indices[i]
            global_idx = matching_indices[sub_idx] if matching_indices is not None else sub_idx
            results.append((
                self.entity_ids[global_idx],
                self.entity_types[global_idx],
                round(float(filtered_scores[i]), 4),
            ))
        return results


    async def search_async(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
        min_score: float = 0.0,
    ) -> List[Tuple[str, str, float]]:
        return await asyncio.to_thread(self.search, query, entity_type, limit, min_score)

