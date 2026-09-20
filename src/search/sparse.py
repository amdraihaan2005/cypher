import re
import json
import sqlite3
from pathlib import Path
from typing import List, Tuple, Optional

from src.mitre.db import get_connection, DEFAULT_DB_PATH


def sanitize_fts_query(query: str) -> str:
    """
    Sanitizes user input into a safe FTS5 query string.
    Strips dangerous characters, handles punctuation, and supports token prefix matching.
    """
    cleaned = query.strip()
    if not cleaned:
        return ""

    if cleaned.startswith('"') and cleaned.endswith('"'):
        return cleaned

    tokens = re.findall(r"[A-Za-z0-9_.-]+", cleaned)
    if not tokens:
        return ""

    fts_tokens = []
    for t in tokens:
        clean_t = t.replace('"', "")
        if clean_t:
            if len(clean_t) >= 3:
                fts_tokens.append(f'"{clean_t}"*')
            else:
                fts_tokens.append(f'"{clean_t}"')

    return " ".join(fts_tokens)


class SparseSearchEngine:
    """
    Sparse keyword search using SQLite FTS5 with BM25 ranking across ALL MITRE ATT&CK entities:
    Tactics, Techniques, Mitigations, Adversary Groups, and Software/Malware.
    """

    def __init__(self, db_path: Optional[Path] = None, conn=None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._owns_conn = conn is None
        self.conn = conn if conn is not None else get_connection(self.db_path)
        self._ensure_fts_table()
        # Warn if FTS index is empty (server started without running build_search_index.py)
        try:
            count = self.conn.execute("SELECT COUNT(*) FROM mitre_entities_fts").fetchone()[0]
            if count == 0:
                print("[SparseSearchEngine] WARNING: FTS index is empty. Run 'python scripts/build_search_index.py' to populate it.")
        except Exception:
            pass

    def close(self):
        if self._owns_conn:
            self.conn.close()

    def _ensure_fts_table(self):
        """Initializes FTS5 virtual table for all MITRE entities."""
        with self.conn:
            self.conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS mitre_entities_fts USING fts5(
                    entity_id,
                    entity_type,
                    name,
                    aliases,
                    tactics,
                    platforms,
                    description,
                    tokenize = 'porter unicode61'
                )
            """)

    def build_index(self):
        """Populates the mitre_entities_fts table with all 1,757+ MITRE entities."""
        records = []

        # 1. Tactics
        cursor = self.conn.execute("SELECT attack_id, name, shortname, description FROM tactics")
        for r in cursor.fetchall():
            records.append((
                r["attack_id"],
                "tactic",
                r["name"],
                r["shortname"],
                r["shortname"],
                "",
                r["description"] or "",
            ))

        # 2. Techniques & Sub-techniques
        cursor = self.conn.execute("SELECT attack_id, name, tactics_json, platforms_json, description FROM techniques")
        for r in cursor.fetchall():
            tactics = " ".join(json.loads(r["tactics_json"] or "[]"))
            platforms = " ".join(json.loads(r["platforms_json"] or "[]"))
            records.append((
                r["attack_id"],
                "technique",
                r["name"],
                "",
                tactics,
                platforms,
                r["description"] or "",
            ))

        # 3. Mitigations
        cursor = self.conn.execute("SELECT attack_id, name, description FROM mitigations")
        for r in cursor.fetchall():
            records.append((
                r["attack_id"],
                "mitigation",
                r["name"],
                "",
                "",
                "",
                r["description"] or "",
            ))

        # 4. Groups (Threat Actors)
        cursor = self.conn.execute("SELECT attack_id, name, aliases_json, description FROM groups")
        for r in cursor.fetchall():
            aliases = " ".join(json.loads(r["aliases_json"] or "[]"))
            records.append((
                r["attack_id"],
                "group",
                r["name"],
                aliases,
                "",
                "",
                r["description"] or "",
            ))

        # 5. Software (Malware & Tools)
        cursor = self.conn.execute("SELECT attack_id, name, type, aliases_json, platforms_json, description FROM software")
        for r in cursor.fetchall():
            aliases = " ".join(json.loads(r["aliases_json"] or "[]"))
            platforms = " ".join(json.loads(r["platforms_json"] or "[]"))
            records.append((
                r["attack_id"],
                "software",
                r["name"],
                aliases,
                r["type"] or "",
                platforms,
                r["description"] or "",
            ))

        with self.conn:
            self.conn.execute("DELETE FROM mitre_entities_fts")
            self.conn.executemany(
                """
                INSERT INTO mitre_entities_fts (
                    entity_id, entity_type, name, aliases, tactics, platforms, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                records,
            )

    def search(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[Tuple[str, str, float]]:
        """
        Executes a BM25 sparse search over all MITRE entities.
        Returns list of (entity_id, entity_type, normalized_score) sorted in descending order.
        """
        fts_query = sanitize_fts_query(query)
        if not fts_query:
            return []

        try:
            # BM25 column weights: entity_id=10.0, entity_type=0.0, name=6.0, aliases=5.0, tactics=2.0, platforms=1.0, description=1.0
            if entity_type:
                sql = """
                    SELECT 
                        entity_id,
                        entity_type,
                        bm25(mitre_entities_fts, 10.0, 0.0, 6.0, 5.0, 2.0, 1.0, 1.0) AS raw_score
                    FROM mitre_entities_fts
                    WHERE mitre_entities_fts MATCH ? AND entity_type = ?
                    ORDER BY raw_score ASC
                    LIMIT ?
                """
                cursor = self.conn.execute(sql, (fts_query, entity_type.strip().lower(), limit))
            else:
                sql = """
                    SELECT 
                        entity_id,
                        entity_type,
                        bm25(mitre_entities_fts, 10.0, 0.0, 6.0, 5.0, 2.0, 1.0, 1.0) AS raw_score
                    FROM mitre_entities_fts
                    WHERE mitre_entities_fts MATCH ?
                    ORDER BY raw_score ASC
                    LIMIT ?
                """
                cursor = self.conn.execute(sql, (fts_query, limit))

            results = cursor.fetchall()
            scored = []
            for row in results:
                raw = row["raw_score"]
                norm_score = abs(raw) / (1.0 + abs(raw))
                scored.append((row["entity_id"], row["entity_type"], round(float(norm_score), 4)))

            return scored
        except sqlite3.OperationalError:
            return []
