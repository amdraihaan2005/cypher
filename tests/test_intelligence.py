import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from src.search.rrf import reciprocal_rank_fusion
from src.intelligence.graph_reasoning import GraphReasoningEngine
from src.api.app import app


class TestThreatIntelligence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = GraphReasoningEngine()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.engine.close()
        cls.client.close()

    def test_rrf_algorithm(self):
        # List 1: dense ranks A=1, B=2, C=3
        dense = [("A", 0.9), ("B", 0.8), ("C", 0.7)]
        # List 2: sparse ranks B=1, A=2, D=3
        sparse = [("B", 10.0), ("A", 8.0), ("D", 5.0)]

        fused = reciprocal_rank_fusion([("dense", dense), ("sparse", sparse)], k=60)
        top_items = [item[0] for item in fused]

        # Both A and B appeared in top 2 of both lists, so they must lead over C and D
        self.assertIn(top_items[0], ["A", "B"])
        self.assertIn(top_items[1], ["A", "B"])
        self.assertIn("C", top_items)
        self.assertIn("D", top_items)

        # Check rank tracking
        item_map = {item[0]: (item[1], item[2]) for item in fused}
        self.assertEqual(item_map["A"][1]["dense"], 1)
        self.assertEqual(item_map["A"][1]["sparse"], 2)

    def test_graph_reasoning_credential_theft_scenario(self):
        query = "attacker dumping credentials from lsass memory using powershell"
        report = self.engine.analyze_narrative(query=query, max_techniques=4)

        # 1. Techniques identified
        self.assertGreater(len(report.identified_techniques), 0)
        tech_ids = [t.attack_id for t in report.identified_techniques]
        self.assertTrue(any(aid.startswith("T1003") or aid.startswith("T1059") for aid in tech_ids))

        # 2. Attribution: Groups identified
        self.assertGreater(len(report.attributed_groups), 0)
        top_group = report.attributed_groups[0]
        self.assertGreater(top_group.overlap_count, 0)
        self.assertGreater(top_group.overlap_ratio, 0.0)

        # 3. Software identified: Mimikatz or PowerShell tools
        self.assertGreater(len(report.identified_software), 0)
        sw_names = [s.software.name for s in report.identified_software]
        self.assertTrue(any("Mimikatz" in n or "PowerShell" in n or "Cobalt" in n for n in sw_names))

        # 4. Defensive Mitigations: Prioritized by coverage
        self.assertGreater(len(report.prioritized_mitigations), 0)
        top_mit = report.prioritized_mitigations[0]
        self.assertGreater(top_mit.coverage_percentage, 0.0)
        self.assertGreaterEqual(top_mit.mitigation_count, 1)

        # 5. Platforms & Tactics compiled
        self.assertGreater(len(report.affected_platforms), 0)
        self.assertGreater(len(report.tactics_involved), 0)

        # 6. Summary metrics present
        summary = report.attack_chain_summary
        self.assertIn("total_techniques_identified", summary)
        self.assertIn("most_likely_actor", summary)
        self.assertIn("top_defensive_priority", summary)

    def test_api_intelligence_analyze_endpoint(self):
        payload = {
            "query": "ransomware encrypting files and deleting volume shadow copies",
            "max_techniques": 3,
            "k": 60,
        }
        response = self.client.post("/api/intelligence/analyze", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["query"], payload["query"])
        self.assertGreater(len(data["identified_techniques"]), 0)
        self.assertGreater(len(data["prioritized_mitigations"]), 0)

    def test_api_search_rrf_endpoint(self):
        response = self.client.get("/api/search/rrf?q=Invoke-Mimikatz&limit=5")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["mode"], "rrf")
        self.assertGreater(len(data["results"]), 0)
        top = data["results"][0]
        self.assertGreater(top["score"], 0.0)

    def test_api_intelligence_narrative_and_chat_endpoints(self):
        # First get a valid report
        res = self.client.post(
            "/api/intelligence/analyze",
            json={"query": "T1059.001 PowerShell execution", "max_techniques": 2},
        )
        self.assertEqual(res.status_code, 200)
        report = res.json()

        # Test narrative endpoint
        narrative_res = self.client.post("/api/intelligence/narrative", json=report)
        self.assertEqual(narrative_res.status_code, 200)
        narrative_data = narrative_res.json()
        self.assertIn("narrative", narrative_data)
        self.assertIn("available", narrative_data)

        # Test chat endpoint
        chat_payload = {
            "report": report,
            "message": "How do we detect this?",
            "history": [],
        }
        chat_res = self.client.post("/api/intelligence/chat", json=chat_payload)
        self.assertEqual(chat_res.status_code, 200)
        chat_data = chat_res.json()
        self.assertIn("reply", chat_data)
        self.assertIn("available", chat_data)


if __name__ == "__main__":
    unittest.main()
