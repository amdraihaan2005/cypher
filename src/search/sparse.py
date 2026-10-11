import re
import json
import sqlite3
import asyncio
from pathlib import Path
from typing import List, Tuple, Optional

from src.mitre.db import get_connection, DEFAULT_DB_PATH


def sanitize_fts_query(query: str) -> str:
    """
    Sanitizes user input into a safe SQLite FTS5 query string.
    - Preserves exact quoted phrases (e.g. "lsass memory").
    - Safely isolates technical identifiers (e.g. T1059.001, CVE-2021-44228, mimikatz.exe).
    - Joins disjunctive clauses with OR, allowing BM25 to mathematically rank term relevance
      via inverse document frequency (IDF).
    """
    cleaned = query.strip()
    if not cleaned:
        return ""

    if cleaned.startswith('"') and cleaned.endswith('"') and len(cleaned) > 2:
        inner = cleaned[1:-1].strip().replace('"', "")
        if inner:
            return f'"{inner}"'

    pattern = r'"([^"]+)"|(\S+)'
    matches = re.findall(pattern, cleaned)

    clauses = []
    for quoted, word in matches:
        if quoted:
            clean_q = re.sub(r"[^\w\s.-]", "", quoted).strip()
            if clean_q and any(c.isalnum() for c in clean_q):
                clauses.append(f'"{clean_q}"')
        elif word:
            clean_w = re.sub(r"[^\w.-]", "", word).strip()
            if clean_w and any(c.isalnum() for c in clean_w):
                if len(clean_w) >= 3:
                    clauses.append(f'"{clean_w}"*')
                else:
                    clauses.append(f'"{clean_w}"')

    return " OR ".join(clauses)


def _safe_json_join(val: Optional[str]) -> str:
    """Safely decodes a JSON list of strings into a space-separated string."""
    if not val:
        return ""
    try:
        parsed = json.loads(val)
        return " ".join(parsed) if isinstance(parsed, list) else str(parsed)
    except Exception:
        return ""


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

        try:
            count = self.conn.execute("SELECT COUNT(*) FROM mitre_entities_fts").fetchone()[0]
            if count == 0:
                print("[SparseSearchEngine] WARNING: mitre_entities_fts is empty. Call engine.build_index() to populate it.")
        except Exception:
            pass

    def close(self):
        if self._owns_conn:
            self.conn.close()

    def __enter__(self) -> "SparseSearchEngine":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


    def _ensure_fts_table(self):
        """Initializes FTS5 virtual table for all MITRE entities if not already created."""
        table_exists = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='mitre_entities_fts'"
        ).fetchone()
        if not table_exists:
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

    def build_index(self) -> int:
        """Populates the mitre_entities_fts table with all MITRE entities."""
        records = []

        # 1. Tactics
        for r in self.conn.execute("SELECT attack_id, name, shortname, description FROM tactics"):
            records.append((
                r["attack_id"], "tactic", r["name"] or "", r["shortname"] or "",
                r["shortname"] or "", "", r["description"] or ""
            ))

        # 2. Techniques & Sub-techniques
        for r in self.conn.execute("SELECT attack_id, name, tactics_json, platforms_json, description FROM techniques"):
            records.append((
                r["attack_id"], "technique", r["name"] or "", "",
                _safe_json_join(r["tactics_json"]), _safe_json_join(r["platforms_json"]),
                r["description"] or ""
            ))

        # 3. Mitigations
        for r in self.conn.execute("SELECT attack_id, name, description FROM mitigations"):
            records.append((
                r["attack_id"], "mitigation", r["name"] or "", "", "", "", r["description"] or ""
            ))

        # 4. Groups
        for r in self.conn.execute("SELECT attack_id, name, aliases_json, description FROM groups"):
            records.append((
                r["attack_id"], "group", r["name"] or "",
                _safe_json_join(r["aliases_json"]), "", "", r["description"] or ""
            ))

        # 5. Software
        for r in self.conn.execute("SELECT attack_id, name, type, aliases_json, platforms_json, description FROM software"):
            records.append((
                r["attack_id"], "software", r["name"] or "",
                _safe_json_join(r["aliases_json"]), r["type"] or "",
                _safe_json_join(r["platforms_json"]), r["description"] or ""
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
        return len(records)

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

        limit = max(1, limit)

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
        except sqlite3.OperationalError as e:
            print(f"[SparseSearchEngine] FTS5 query warning for '{query}': {e}")
            return []

    async def search_async(
        self,
        query: str,
        entity_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[Tuple[str, str, float]]:
        """Asynchronously executes BM25 search offloaded to a threadpool worker."""
        return await asyncio.to_thread(self.search, query, entity_type, limit)

