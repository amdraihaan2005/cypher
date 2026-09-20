import json
import sqlite3
from pathlib import Path
from typing import List, Tuple, Optional
import numpy as np
from fastembed import TextEmbedding

from src.mitre.db import get_connection, DEFAULT_DB_PATH

DEFAULT_EMBEDDINGS_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "mitre" / "embeddings.npz"
DEFAULT_MODEL_NAME = "BAAI/bge-small-en-v1.5"


class DenseSearchEngine:
    """
    Dense semantic vector search using FastEmbed ONNX embeddings and NumPy cosine similarity
    covering ALL MITRE ATT&CK entities: Tactics, Techniques, Mitigations, Groups, Software.
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

        self._load_cached_embeddings()

    @property
    def model(self) -> TextEmbedding:
        if self._model is None:
            self._model = TextEmbedding(model_name=self.model_name)
        return self._model

    def _load_cached_embeddings(self) -> bool:
        """Loads precomputed vectors from disk if available."""
        if self.embeddings_path.exists():
            try:
                data = np.load(str(self.embeddings_path), allow_pickle=True)
                if "entity_ids" in data and "entity_types" in data:
                    self.entity_ids = [str(x) for x in data["entity_ids"]]
                    self.entity_types = [str(x) for x in data["entity_types"]]
                    self.names = [str(x) for x in data["names"]]
                    self.vectors = data["vectors"].astype(np.float32)
                    return True
            except Exception:
                pass
        return False

    def build_index(self):
        """Generates and persists embeddings for ALL 1,757+ MITRE entities."""
        conn = get_connection(self.db_path)
        try:
            # 1. Tactics (15)
            tac_rows = conn.execute("SELECT attack_id, name, shortname, description FROM tactics ORDER BY attack_id").fetchall()
            # 2. Techniques (697)
            tech_rows = conn.execute("SELECT attack_id, name, tactics_json, platforms_json, detection, description FROM techniques ORDER BY attack_id").fetchall()
            # 3. Mitigations (44)
            mit_rows = conn.execute("SELECT attack_id, name, description FROM mitigations ORDER BY attack_id").fetchall()
            # 4. Groups (176)
            grp_rows = conn.execute("SELECT attack_id, name, aliases_json, description FROM groups ORDER BY attack_id").fetchall()
            # 5. Software (825)
            sw_rows = conn.execute("SELECT attack_id, name, type, aliases_json, platforms_json, description FROM software ORDER BY attack_id").fetchall()
        finally:
            conn.close()

        entity_ids = []
        entity_types = []
        names = []
        documents = []

        # Process Tactics
        for r in tac_rows:
            entity_ids.append(r["attack_id"])
            entity_types.append("tactic")
            names.append(r["name"])
            desc = r["description"] or ""
            documents.append(f"{r['attack_id']}: {r['name']} [ATT&CK Tactic]. Goal: {r['name']}. Shortname: {r['shortname']}. {desc}")

        # Process Techniques
        for r in tech_rows:
            entity_ids.append(r["attack_id"])
            entity_types.append("technique")
            names.append(r["name"])
            tactics = ", ".join(json.loads(r["tactics_json"] or "[]"))
            platforms = ", ".join(json.loads(r["platforms_json"] or "[]"))
            detection = r["detection"] or ""
            desc = r["description"] or ""
            documents.append(f"{r['attack_id']}: {r['name']} [ATT&CK Technique]. Tactics: {tactics}. Platforms: {platforms}. Detection: {detection}. {desc}")

        # Process Mitigations
        for r in mit_rows:
            entity_ids.append(r["attack_id"])
            entity_types.append("mitigation")
            names.append(r["name"])
            desc = r["description"] or ""
            documents.append(f"{r['attack_id']}: {r['name']} [Defensive Mitigation / Security Control]. {desc}")

        # Process Groups (APTs)
        for r in grp_rows:
            entity_ids.append(r["attack_id"])
            entity_types.append("group")
            names.append(r["name"])
            aliases = ", ".join(json.loads(r["aliases_json"] or "[]"))
            desc = r["description"] or ""
            documents.append(f"{r['attack_id']}: {r['name']} [Adversary Threat Group / APT]. Known aliases: {aliases}. {desc}")

        # Process Software (Malware & Tools)
        for r in sw_rows:
            entity_ids.append(r["attack_id"])
            entity_types.append("software")
            names.append(r["name"])
            aliases = ", ".join(json.loads(r["aliases_json"] or "[]"))
            platforms = ", ".join(json.loads(r["platforms_json"] or "[]"))
            desc = r["description"] or ""
            documents.append(f"{r['attack_id']}: {r['name']} [{r['type'].capitalize() if r['type'] else 'Software'} Tool]. Known aliases: {aliases}. Platforms: {platforms}. {desc}")

        print(f"[DenseSearchEngine] Embedding all {len(documents)} MITRE entities ({len(tac_rows)} tactics, {len(tech_rows)} techniques, {len(mit_rows)} mitigations, {len(grp_rows)} groups, {len(sw_rows)} software) via {self.model_name}...")

        # Batch embed
        embeddings = list(self.model.embed(documents, batch_size=128))
        vectors = np.array(embeddings, dtype=np.float32)

        # L2-normalize
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        normalized_vectors = vectors / norms

        self.embeddings_path.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(
            str(self.embeddings_path),
            entity_ids=np.array(entity_ids),
            entity_types=np.array(entity_types),
            names=np.array(names),
            vectors=normalized_vectors,
        )

        self.entity_ids = entity_ids
        self.entity_types = entity_types
        self.names = names
        self.vectors = normalized_vectors
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
                self.build_index()

        cleaned = query.strip()
        if not cleaned:
            return []

        # Embed query and normalize
        query_emb = list(self.model.embed([cleaned]))[0]
        q_vec = np.array(query_emb, dtype=np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm > 0:
            q_vec = q_vec / q_norm

        # Filter candidate vectors if entity_type is requested
        if entity_type:
            target_type = entity_type.strip().lower()
            matching_indices = [i for i, t in enumerate(self.entity_types) if t == target_type]
            if not matching_indices:
                return []
            candidate_vectors = self.vectors[matching_indices]
            sub_similarities = np.dot(candidate_vectors, q_vec)
            top_k = min(limit, len(matching_indices))
            sub_top = np.argpartition(-sub_similarities, top_k)[:top_k]
            sub_top = sub_top[np.argsort(-sub_similarities[sub_top])]

            results = []
            for sub_idx in sub_top:
                score = round(float(sub_similarities[sub_idx]), 4)
                if score < min_score:
                    continue
                global_idx = matching_indices[sub_idx]
                results.append((
                    self.entity_ids[global_idx],
                    self.entity_types[global_idx],
                    score,
                ))
            return results
        else:
            # Search across all 1,757 entities
            similarities = np.dot(self.vectors, q_vec)
            top_k = min(limit, len(self.entity_ids))
            top_indices = np.argpartition(-similarities, top_k)[:top_k]
            top_indices = top_indices[np.argsort(-similarities[top_indices])]

            results = []
            for idx in top_indices:
                score = round(float(similarities[idx]), 4)
                if score < min_score:
                    continue
                results.append((
                    self.entity_ids[idx],
                    self.entity_types[idx],
                    score,
                ))
            return results
