import sqlite3
import json
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from src.mitre.schema import (
    TacticItem,
    TechniqueItem,
    MitigationItem,
    GroupItem,
    SoftwareItem,
    TechniqueDetail,
    TacticDetail,
    MitigationDetail,
    GroupDetail,
    SoftwareDetail,
)

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "mitre" / "mitre_attack.db"


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target = db_path or DEFAULT_DB_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection):
    """Initializes the database schema with appropriate tables and indexes."""
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tactics (
                attack_id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                shortname TEXT NOT NULL,
                description TEXT,
                url TEXT
            );

            CREATE TABLE IF NOT EXISTS techniques (
                attack_id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                is_subtechnique INTEGER NOT NULL DEFAULT 0,
                parent_attack_id TEXT,
                tactics_json TEXT,
                platforms_json TEXT,
                data_sources_json TEXT,
                detection TEXT,
                url TEXT
            );

            CREATE TABLE IF NOT EXISTS mitigations (
                attack_id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                description TEXT,
                url TEXT
            );

            CREATE TABLE IF NOT EXISTS groups (
                attack_id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                aliases_json TEXT,
                description TEXT,
                url TEXT
            );

            CREATE TABLE IF NOT EXISTS software (
                attack_id TEXT PRIMARY KEY,
                stix_id TEXT UNIQUE,
                name TEXT NOT NULL,
                type TEXT,
                aliases_json TEXT,
                platforms_json TEXT,
                description TEXT,
                url TEXT
            );

            -- Relationship Junction Tables
            CREATE TABLE IF NOT EXISTS technique_mitigations (
                technique_attack_id TEXT NOT NULL,
                mitigation_attack_id TEXT NOT NULL,
                description TEXT,
                PRIMARY KEY (technique_attack_id, mitigation_attack_id),
                FOREIGN KEY (technique_attack_id) REFERENCES techniques(attack_id) ON DELETE CASCADE,
                FOREIGN KEY (mitigation_attack_id) REFERENCES mitigations(attack_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_techniques (
                group_attack_id TEXT NOT NULL,
                technique_attack_id TEXT NOT NULL,
                description TEXT,
                PRIMARY KEY (group_attack_id, technique_attack_id),
                FOREIGN KEY (group_attack_id) REFERENCES groups(attack_id) ON DELETE CASCADE,
                FOREIGN KEY (technique_attack_id) REFERENCES techniques(attack_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS software_techniques (
                software_attack_id TEXT NOT NULL,
                technique_attack_id TEXT NOT NULL,
                description TEXT,
                PRIMARY KEY (software_attack_id, technique_attack_id),
                FOREIGN KEY (software_attack_id) REFERENCES software(attack_id) ON DELETE CASCADE,
                FOREIGN KEY (technique_attack_id) REFERENCES techniques(attack_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS group_software (
                group_attack_id TEXT NOT NULL,
                software_attack_id TEXT NOT NULL,
                description TEXT,
                PRIMARY KEY (group_attack_id, software_attack_id),
                FOREIGN KEY (group_attack_id) REFERENCES groups(attack_id) ON DELETE CASCADE,
                FOREIGN KEY (software_attack_id) REFERENCES software(attack_id) ON DELETE CASCADE
            );

            -- Technique to Tactic mapping for fast faceted filtering
            CREATE TABLE IF NOT EXISTS technique_tactics (
                technique_attack_id TEXT NOT NULL,
                tactic_shortname TEXT NOT NULL,
                PRIMARY KEY (technique_attack_id, tactic_shortname),
                FOREIGN KEY (technique_attack_id) REFERENCES techniques(attack_id) ON DELETE CASCADE
            );

            -- Technique to Platform mapping
            CREATE TABLE IF NOT EXISTS technique_platforms (
                technique_attack_id TEXT NOT NULL,
                platform TEXT NOT NULL,
                PRIMARY KEY (technique_attack_id, platform),
                FOREIGN KEY (technique_attack_id) REFERENCES techniques(attack_id) ON DELETE CASCADE
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_tech_parent ON techniques(parent_attack_id);
            CREATE INDEX IF NOT EXISTS idx_tech_name ON techniques(name);
            CREATE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
            CREATE INDEX IF NOT EXISTS idx_software_name ON software(name);
            CREATE INDEX IF NOT EXISTS idx_tactics_shortname ON tactics(shortname);
            CREATE INDEX IF NOT EXISTS idx_tt_tactic ON technique_tactics(tactic_shortname);
            CREATE INDEX IF NOT EXISTS idx_tp_platform ON technique_platforms(platform);
        """)


def populate_db(
    conn: sqlite3.Connection,
    tactics: List[TacticItem],
    techniques: List[TechniqueItem],
    mitigations: List[MitigationItem],
    groups: List[GroupItem],
    software: List[SoftwareItem],
    relationships: Dict[str, List[Tuple[str, str, str]]],
):
    """Populates all normalized tables in an atomic transaction."""
    with conn:
        # Clear existing
        conn.execute("DELETE FROM technique_tactics")
        conn.execute("DELETE FROM technique_platforms")
        conn.execute("DELETE FROM technique_mitigations")
        conn.execute("DELETE FROM group_techniques")
        conn.execute("DELETE FROM software_techniques")
        conn.execute("DELETE FROM techniques")
        conn.execute("DELETE FROM tactics")
        conn.execute("DELETE FROM mitigations")
        conn.execute("DELETE FROM groups")
        conn.execute("DELETE FROM software")

        # Insert tactics
        conn.executemany(
            """
            INSERT INTO tactics (attack_id, stix_id, name, shortname, description, url)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [(t.attack_id, t.stix_id, t.name, t.shortname, t.description, t.url) for t in tactics],
        )

        # Insert techniques
        conn.executemany(
            """
            INSERT INTO techniques (
                attack_id, stix_id, name, description, is_subtechnique,
                parent_attack_id, tactics_json, platforms_json, data_sources_json,
                detection, url
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    t.attack_id,
                    t.stix_id,
                    t.name,
                    t.description,
                    1 if t.is_subtechnique else 0,
                    t.parent_attack_id,
                    json.dumps(t.tactics),
                    json.dumps(t.platforms),
                    json.dumps(t.data_sources),
                    t.detection,
                    t.url,
                )
                for t in techniques
            ],
        )

        # Insert mitigations
        conn.executemany(
            """
            INSERT INTO mitigations (attack_id, stix_id, name, description, url)
            VALUES (?, ?, ?, ?, ?)
            """,
            [(m.attack_id, m.stix_id, m.name, m.description, m.url) for m in mitigations],
        )

        # Insert groups
        conn.executemany(
            """
            INSERT INTO groups (attack_id, stix_id, name, aliases_json, description, url)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [(g.attack_id, g.stix_id, g.name, json.dumps(g.aliases), g.description, g.url) for g in groups],
        )

        # Insert software
        conn.executemany(
            """
            INSERT INTO software (attack_id, stix_id, name, type, aliases_json, platforms_json, description, url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (s.attack_id, s.stix_id, s.name, s.type, json.dumps(s.aliases), json.dumps(s.platforms), s.description, s.url)
                for s in software
            ],
        )

        # Faceted indexes: technique_tactics & technique_platforms
        tt_records = []
        tp_records = []
        for t in techniques:
            for tac in t.tactics:
                tt_records.append((t.attack_id, tac))
            for plat in t.platforms:
                tp_records.append((t.attack_id, plat))

        conn.executemany(
            "INSERT OR IGNORE INTO technique_tactics (technique_attack_id, tactic_shortname) VALUES (?, ?)",
            tt_records,
        )
        conn.executemany(
            "INSERT OR IGNORE INTO technique_platforms (technique_attack_id, platform) VALUES (?, ?)",
            tp_records,
        )

        # Relationships
        conn.executemany(
            """
            INSERT OR IGNORE INTO technique_mitigations (technique_attack_id, mitigation_attack_id, description)
            VALUES (?, ?, ?)
            """,
            relationships["technique_mitigations"],
        )

        conn.executemany(
            """
            INSERT OR IGNORE INTO group_techniques (group_attack_id, technique_attack_id, description)
            VALUES (?, ?, ?)
            """,
            relationships["group_techniques"],
        )

        conn.executemany(
            """
            INSERT OR IGNORE INTO software_techniques (software_attack_id, technique_attack_id, description)
            VALUES (?, ?, ?)
            """,
            relationships["software_techniques"],
        )

        if "group_software" in relationships:
            conn.executemany(
                """
                INSERT OR IGNORE INTO group_software (group_attack_id, software_attack_id, description)
                VALUES (?, ?, ?)
                """,
                relationships["group_software"],
            )


class MitreRepository:
    """Repository providing fast query APIs over the normalized MITRE database."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.conn = get_connection(self.db_path)

    def close(self):
        self.conn.close()

    def _row_to_technique(self, row: sqlite3.Row) -> TechniqueItem:
        return TechniqueItem(
            attack_id=row["attack_id"],
            stix_id=row["stix_id"],
            name=row["name"],
            description=row["description"] or "",
            is_subtechnique=bool(row["is_subtechnique"]),
            parent_attack_id=row["parent_attack_id"],
            tactics=json.loads(row["tactics_json"] or "[]"),
            platforms=json.loads(row["platforms_json"] or "[]"),
            data_sources=json.loads(row["data_sources_json"] or "[]"),
            detection=row["detection"],
            url=row["url"],
        )

    def get_technique(self, attack_id: str) -> Optional[TechniqueDetail]:
        """Retrieves a technique with all subtechniques, mitigations, groups, and software."""
        clean_id = attack_id.strip().upper()
        cursor = self.conn.execute("SELECT * FROM techniques WHERE attack_id = ?", (clean_id,))
        row = cursor.fetchone()
        if not row:
            return None

        tech = self._row_to_technique(row)

        # Subtechniques
        sub_cursor = self.conn.execute(
            "SELECT * FROM techniques WHERE parent_attack_id = ? ORDER BY attack_id",
            (clean_id,),
        )
        subtechniques = [self._row_to_technique(r) for r in sub_cursor.fetchall()]

        # Mitigations
        mit_cursor = self.conn.execute(
            """
            SELECT m.* FROM mitigations m
            JOIN technique_mitigations tm ON m.attack_id = tm.mitigation_attack_id
            WHERE tm.technique_attack_id = ?
            ORDER BY m.name
            """,
            (clean_id,),
        )
        mitigations = [
            MitigationItem(
                stix_id=r["stix_id"],
                attack_id=r["attack_id"],
                name=r["name"],
                description=r["description"] or "",
                url=r["url"],
            )
            for r in mit_cursor.fetchall()
        ]

        # Threat Groups
        grp_cursor = self.conn.execute(
            """
            SELECT g.* FROM groups g
            JOIN group_techniques gt ON g.attack_id = gt.group_attack_id
            WHERE gt.technique_attack_id = ?
            ORDER BY g.name
            """,
            (clean_id,),
        )
        groups = [
            GroupItem(
                stix_id=r["stix_id"],
                attack_id=r["attack_id"],
                name=r["name"],
                aliases=json.loads(r["aliases_json"] or "[]"),
                description=r["description"] or "",
                url=r["url"],
            )
            for r in grp_cursor.fetchall()
        ]

        # Software
        sw_cursor = self.conn.execute(
            """
            SELECT s.* FROM software s
            JOIN software_techniques st ON s.attack_id = st.software_attack_id
            WHERE st.technique_attack_id = ?
            ORDER BY s.name
            """,
            (clean_id,),
        )
        software = [
            SoftwareItem(
                stix_id=r["stix_id"],
                attack_id=r["attack_id"],
                name=r["name"],
                type=r["type"] or "software",
                aliases=json.loads(r["aliases_json"] or "[]"),
                platforms=json.loads(r["platforms_json"] or "[]"),
                description=r["description"] or "",
                url=r["url"],
            )
            for r in sw_cursor.fetchall()
        ]

        return TechniqueDetail(
            technique=tech,
            subtechniques=subtechniques,
            mitigations=mitigations,
            groups=groups,
            software=software,
        )

    def _row_to_tactic(self, row: sqlite3.Row) -> TacticItem:
        return TacticItem(
            stix_id=row["stix_id"],
            attack_id=row["attack_id"],
            name=row["name"],
            shortname=row["shortname"],
            description=row["description"] or "",
            url=row["url"],
        )

    def _row_to_mitigation(self, row: sqlite3.Row) -> MitigationItem:
        return MitigationItem(
            stix_id=row["stix_id"],
            attack_id=row["attack_id"],
            name=row["name"],
            description=row["description"] or "",
            url=row["url"],
        )

    def _row_to_group(self, row: sqlite3.Row) -> GroupItem:
        return GroupItem(
            stix_id=row["stix_id"],
            attack_id=row["attack_id"],
            name=row["name"],
            aliases=json.loads(row["aliases_json"] or "[]"),
            description=row["description"] or "",
            url=row["url"],
        )

    def _row_to_software(self, row: sqlite3.Row) -> SoftwareItem:
        return SoftwareItem(
            stix_id=row["stix_id"],
            attack_id=row["attack_id"],
            name=row["name"],
            type=row["type"] or "software",
            aliases=json.loads(row["aliases_json"] or "[]"),
            platforms=json.loads(row["platforms_json"] or "[]"),
            description=row["description"] or "",
            url=row["url"],
        )

    def list_tactics(self) -> List[TacticItem]:
        cursor = self.conn.execute("SELECT * FROM tactics ORDER BY attack_id")
        return [self._row_to_tactic(r) for r in cursor.fetchall()]

    def get_tactic(self, identifier: str) -> Optional[TacticDetail]:
        """Lookup tactic by attack_id (e.g. TA0001) or shortname (e.g. initial-access)."""
        clean_id = identifier.strip().lower()
        cursor = self.conn.execute(
            "SELECT * FROM tactics WHERE LOWER(attack_id) = ? OR LOWER(shortname) = ?",
            (clean_id, clean_id),
        )
        row = cursor.fetchone()
        if not row:
            return None
        tactic = self._row_to_tactic(row)
        techniques = self.get_techniques_by_tactic(tactic.shortname)
        return TacticDetail(tactic=tactic, techniques=techniques)

    def list_techniques(
        self,
        limit: int = 50,
        offset: int = 0,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        is_subtechnique: Optional[bool] = None,
    ) -> Tuple[List[TechniqueItem], int]:
        """Paginated techniques lookup with optional filtering by tactic, platform, sub-technique."""
        conditions = []
        params = []
        joins = []

        if tactic:
            clean_tac = tactic.strip().lower().replace(" ", "-")
            joins.append("JOIN technique_tactics tt ON t.attack_id = tt.technique_attack_id")
            conditions.append("tt.tactic_shortname = ?")
            params.append(clean_tac)

        if platform:
            joins.append("JOIN technique_platforms tp ON t.attack_id = tp.technique_attack_id")
            conditions.append("LOWER(tp.platform) = LOWER(?)")
            params.append(platform.strip())

        if is_subtechnique is not None:
            conditions.append("t.is_subtechnique = ?")
            params.append(1 if is_subtechnique else 0)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        join_clause = " ".join(joins)

        # Count total matches
        count_sql = f"SELECT COUNT(DISTINCT t.attack_id) FROM techniques t {join_clause} {where_clause}"
        total = self.conn.execute(count_sql, tuple(params)).fetchone()[0]

        # Fetch records
        data_sql = f"""
            SELECT DISTINCT t.* FROM techniques t
            {join_clause}
            {where_clause}
            ORDER BY t.attack_id
            LIMIT ? OFFSET ?
        """
        fetch_params = params + [limit, offset]
        rows = self.conn.execute(data_sql, tuple(fetch_params)).fetchall()
        items = [self._row_to_technique(r) for r in rows]
        return items, total

    def get_techniques_by_tactic(self, tactic_shortname: str) -> List[TechniqueItem]:
        clean_tac = tactic_shortname.strip().lower().replace(" ", "-")
        cursor = self.conn.execute(
            """
            SELECT t.* FROM techniques t
            JOIN technique_tactics tt ON t.attack_id = tt.technique_attack_id
            WHERE tt.tactic_shortname = ?
            ORDER BY t.attack_id
            """,
            (clean_tac,),
        )
        return [self._row_to_technique(r) for r in cursor.fetchall()]

    def get_techniques_by_platform(self, platform: str) -> List[TechniqueItem]:
        cursor = self.conn.execute(
            """
            SELECT t.* FROM techniques t
            JOIN technique_platforms tp ON t.attack_id = tp.technique_attack_id
            WHERE LOWER(tp.platform) = LOWER(?)
            ORDER BY t.attack_id
            """,
            (platform.strip(),),
        )
        return [self._row_to_technique(r) for r in cursor.fetchall()]

    def list_mitigations(self, limit: int = 50, offset: int = 0) -> Tuple[List[MitigationItem], int]:
        total = self.conn.execute("SELECT COUNT(*) FROM mitigations").fetchone()[0]
        cursor = self.conn.execute(
            "SELECT * FROM mitigations ORDER BY attack_id LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._row_to_mitigation(r) for r in cursor.fetchall()], total

    def get_mitigation(self, attack_id: str) -> Optional[MitigationDetail]:
        clean_id = attack_id.strip().upper()
        cursor = self.conn.execute("SELECT * FROM mitigations WHERE attack_id = ?", (clean_id,))
        row = cursor.fetchone()
        if not row:
            return None
        mitigation = self._row_to_mitigation(row)

        tech_cursor = self.conn.execute(
            """
            SELECT t.* FROM techniques t
            JOIN technique_mitigations tm ON t.attack_id = tm.technique_attack_id
            WHERE tm.mitigation_attack_id = ?
            ORDER BY t.attack_id
            """,
            (clean_id,),
        )
        techniques = [self._row_to_technique(r) for r in tech_cursor.fetchall()]
        return MitigationDetail(mitigation=mitigation, techniques=techniques)

    def list_groups(self, limit: int = 50, offset: int = 0) -> Tuple[List[GroupItem], int]:
        total = self.conn.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
        cursor = self.conn.execute(
            "SELECT * FROM groups ORDER BY attack_id LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [self._row_to_group(r) for r in cursor.fetchall()], total

    def get_group(self, attack_id: str) -> Optional[GroupDetail]:
        clean_id = attack_id.strip().upper()
        cursor = self.conn.execute("SELECT * FROM groups WHERE attack_id = ?", (clean_id,))
        row = cursor.fetchone()
        if not row:
            return None
        group = self._row_to_group(row)

        tech_cursor = self.conn.execute(
            """
            SELECT t.* FROM techniques t
            JOIN group_techniques gt ON t.attack_id = gt.technique_attack_id
            WHERE gt.group_attack_id = ?
            ORDER BY t.attack_id
            """,
            (clean_id,),
        )
        techniques = [self._row_to_technique(r) for r in tech_cursor.fetchall()]

        sw_cursor = self.conn.execute(
            """
            SELECT s.* FROM software s
            JOIN group_software gs ON s.attack_id = gs.software_attack_id
            WHERE gs.group_attack_id = ?
            ORDER BY s.name
            """,
            (clean_id,),
        )
        software = [self._row_to_software(r) for r in sw_cursor.fetchall()]
        return GroupDetail(group=group, techniques=techniques, software=software)

    def list_software(
        self,
        limit: int = 50,
        offset: int = 0,
        type: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> Tuple[List[SoftwareItem], int]:
        conditions = []
        params = []
        if type:
            conditions.append("LOWER(type) = LOWER(?)")
            params.append(type.strip())
        if platform:
            conditions.append("platforms_json LIKE ?")
            params.append(f"%{platform.strip()}%")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        count_sql = f"SELECT COUNT(*) FROM software {where_clause}"
        total = self.conn.execute(count_sql, tuple(params)).fetchone()[0]

        data_sql = f"SELECT * FROM software {where_clause} ORDER BY attack_id LIMIT ? OFFSET ?"
        fetch_params = params + [limit, offset]
        cursor = self.conn.execute(data_sql, tuple(fetch_params))
        return [self._row_to_software(r) for r in cursor.fetchall()], total

    def get_software(self, attack_id: str) -> Optional[SoftwareDetail]:
        clean_id = attack_id.strip().upper()
        cursor = self.conn.execute("SELECT * FROM software WHERE attack_id = ?", (clean_id,))
        row = cursor.fetchone()
        if not row:
            return None
        software = self._row_to_software(row)

        tech_cursor = self.conn.execute(
            """
            SELECT t.* FROM techniques t
            JOIN software_techniques st ON t.attack_id = st.technique_attack_id
            WHERE st.software_attack_id = ?
            ORDER BY t.attack_id
            """,
            (clean_id,),
        )
        techniques = [self._row_to_technique(r) for r in tech_cursor.fetchall()]

        grp_cursor = self.conn.execute(
            """
            SELECT g.* FROM groups g
            JOIN group_software gs ON g.attack_id = gs.group_attack_id
            WHERE gs.software_attack_id = ?
            ORDER BY g.name
            """,
            (clean_id,),
        )
        groups = [self._row_to_group(r) for r in grp_cursor.fetchall()]
        return SoftwareDetail(software=software, techniques=techniques, groups=groups)

    def search_techniques(self, query: str, limit: int = 20) -> List[TechniqueItem]:
        """Prefix/keyword search across attack_id and name."""
        pattern = f"%{query.strip()}%"
        cursor = self.conn.execute(
            """
            SELECT * FROM techniques
            WHERE attack_id LIKE ? OR name LIKE ?
            ORDER BY (CASE WHEN attack_id LIKE ? THEN 0 ELSE 1 END), attack_id
            LIMIT ?
            """,
            (pattern, pattern, pattern, limit),
        )
        return [self._row_to_technique(r) for r in cursor.fetchall()]

    def search_all(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Unified search across techniques, groups, and software."""
        pattern = f"%{query.strip()}%"
        
        techs = self.search_techniques(query, limit=limit)
        
        grp_cursor = self.conn.execute(
            """
            SELECT * FROM groups
            WHERE attack_id LIKE ? OR name LIKE ? OR aliases_json LIKE ?
            LIMIT ?
            """,
            (pattern, pattern, pattern, limit),
        )
        groups = [self._row_to_group(r) for r in grp_cursor.fetchall()]

        sw_cursor = self.conn.execute(
            """
            SELECT * FROM software
            WHERE attack_id LIKE ? OR name LIKE ? OR aliases_json LIKE ?
            LIMIT ?
            """,
            (pattern, pattern, pattern, limit),
        )
        software = [self._row_to_software(r) for r in sw_cursor.fetchall()]

        return {
            "query": query,
            "techniques": techs,
            "groups": groups,
            "software": software,
        }

    def get_statistics(self) -> Dict[str, int]:
        counts = {}
        for table in [
            "tactics",
            "techniques",
            "mitigations",
            "groups",
            "software",
            "technique_mitigations",
            "group_techniques",
            "software_techniques",
            "group_software",
        ]:
            c = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            counts[table] = c
        return counts
