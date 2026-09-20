import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.mitre.db import MitreRepository


class TestMitreKnowledgeEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = MitreRepository()

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()

    def test_database_counts(self):
        stats = self.repo.get_statistics()
        self.assertGreaterEqual(stats["tactics"], 14)
        self.assertGreaterEqual(stats["techniques"], 600)
        self.assertGreaterEqual(stats["mitigations"], 40)
        self.assertGreaterEqual(stats["groups"], 140)
        self.assertGreaterEqual(stats["technique_mitigations"], 1000)

    def test_lookup_technique_t1059(self):
        detail = self.repo.get_technique("T1059")
        self.assertIsNotNone(detail)
        self.assertEqual(detail.technique.attack_id, "T1059")
        self.assertEqual(detail.technique.name, "Command and Scripting Interpreter")
        self.assertIn("execution", detail.technique.tactics)
        self.assertGreater(len(detail.subtechniques), 5)
        self.assertGreater(len(detail.mitigations), 3)

    def test_lookup_subtechnique_powershell(self):
        detail = self.repo.get_technique("T1059.001")
        self.assertIsNotNone(detail)
        self.assertEqual(detail.technique.attack_id, "T1059.001")
        self.assertEqual(detail.technique.name, "PowerShell")
        self.assertTrue(detail.technique.is_subtechnique)
        self.assertEqual(detail.technique.parent_attack_id, "T1059")
        self.assertIn("Windows", detail.technique.platforms)

    def test_list_tactics(self):
        tactics = self.repo.list_tactics()
        self.assertGreaterEqual(len(tactics), 14)
        shortnames = [t.shortname for t in tactics]
        self.assertIn("initial-access", shortnames)
        self.assertIn("execution", shortnames)
        self.assertIn("persistence", shortnames)
        self.assertIn("privilege-escalation", shortnames)

    def test_techniques_by_tactic(self):
        techs = self.repo.get_techniques_by_tactic("initial-access")
        self.assertGreater(len(techs), 5)
        ids = [t.attack_id for t in techs]
        self.assertIn("T1190", ids)  # Exploit Public-Facing Application

    def test_search_techniques(self):
        results = self.repo.search_techniques("Injection")
        self.assertGreater(len(results), 0)
        names = [r.name for r in results]
        self.assertTrue(any("Process Injection" in n for n in names))


if __name__ == "__main__":
    unittest.main()
