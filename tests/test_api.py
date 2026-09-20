import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from src.api.app import app


class TestMitreAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_check(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["database_connected"])
        self.assertGreaterEqual(data["statistics"]["techniques"], 600)

    def test_stats_endpoint(self):
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("tactics", data)
        self.assertIn("techniques", data)
        self.assertIn("mitigations", data)
        self.assertIn("groups", data)
        self.assertIn("software", data)
        self.assertGreaterEqual(data["tactics"], 14)

    def test_list_tactics(self):
        response = self.client.get("/api/tactics")
        self.assertEqual(response.status_code, 200)
        tactics = response.json()
        self.assertGreaterEqual(len(tactics), 14)
        shortnames = [t["shortname"] for t in tactics]
        self.assertIn("initial-access", shortnames)
        self.assertIn("execution", shortnames)
        self.assertIn("persistence", shortnames)

    def test_get_tactic_by_shortname_and_id(self):
        # By shortname
        res1 = self.client.get("/api/tactics/initial-access")
        self.assertEqual(res1.status_code, 200)
        d1 = res1.json()
        self.assertEqual(d1["tactic"]["shortname"], "initial-access")
        self.assertGreater(len(d1["techniques"]), 0)

        # By attack_id
        res2 = self.client.get("/api/tactics/TA0001")
        self.assertEqual(res2.status_code, 200)
        d2 = res2.json()
        self.assertEqual(d2["tactic"]["attack_id"], "TA0001")

        # Not found
        res3 = self.client.get("/api/tactics/not-a-real-tactic")
        self.assertEqual(res3.status_code, 404)

    def test_list_techniques_paginated(self):
        response = self.client.get("/api/techniques?limit=10&offset=0")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["items"]), 10)
        self.assertGreaterEqual(data["total"], 600)
        self.assertTrue(data["has_more"])

    def test_filter_techniques_by_tactic(self):
        response = self.client.get("/api/techniques?tactic=execution&limit=20")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["items"]), 0)
        for item in data["items"]:
            self.assertIn("execution", item["tactics"])

    def test_filter_techniques_by_platform(self):
        response = self.client.get("/api/techniques?platform=Windows&limit=20")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["items"]), 0)
        for item in data["items"]:
            self.assertIn("Windows", item["platforms"])

    def test_get_technique_deep_graph(self):
        # Query T1059: Command and Scripting Interpreter
        response = self.client.get("/api/techniques/T1059")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        # Validate technique info
        self.assertEqual(data["technique"]["attack_id"], "T1059")
        self.assertEqual(data["technique"]["name"], "Command and Scripting Interpreter")

        # Validate graph cross-links
        self.assertGreater(len(data["subtechniques"]), 0)
        self.assertGreater(len(data["mitigations"]), 0)
        self.assertGreater(len(data["groups"]), 0)
        self.assertGreater(len(data["software"]), 0)

        # 404 test
        not_found = self.client.get("/api/techniques/T99999")
        self.assertEqual(not_found.status_code, 404)

    def test_get_mitigations(self):
        # List
        res_list = self.client.get("/api/mitigations?limit=10")
        self.assertEqual(res_list.status_code, 200)
        data = res_list.json()
        self.assertGreaterEqual(data["total"], 40)

        # Detail on M1032 (Multi-factor Authentication)
        res_detail = self.client.get("/api/mitigations/M1032")
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.json()
        self.assertEqual(detail["mitigation"]["name"], "Multi-factor Authentication")
        self.assertGreater(len(detail["techniques"]), 10)

        # 404 test
        self.assertEqual(self.client.get("/api/mitigations/M9999").status_code, 404)

    def test_get_groups(self):
        # List
        res_list = self.client.get("/api/groups?limit=10")
        self.assertEqual(res_list.status_code, 200)
        data = res_list.json()
        self.assertGreaterEqual(data["total"], 140)

        # Detail on G0016 (APT29)
        res_detail = self.client.get("/api/groups/G0016")
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.json()
        self.assertEqual(detail["group"]["name"], "APT29")
        self.assertIn("Cozy Bear", detail["group"]["aliases"])
        self.assertGreater(len(detail["techniques"]), 20)

        # 404 test
        self.assertEqual(self.client.get("/api/groups/G9999").status_code, 404)

    def test_get_software(self):
        # List
        res_list = self.client.get("/api/software?limit=10")
        self.assertEqual(res_list.status_code, 200)
        data = res_list.json()
        self.assertGreaterEqual(data["total"], 700)

        # Detail on S0002 (Mimikatz)
        res_detail = self.client.get("/api/software/S0002")
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.json()
        self.assertEqual(detail["software"]["name"], "Mimikatz")
        self.assertGreater(len(detail["techniques"]), 5)

        # 404 test
        self.assertEqual(self.client.get("/api/software/S9999").status_code, 404)

    def test_unified_search(self):
        # Search for powershell
        response = self.client.get("/api/search?q=powershell")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["query"], "powershell")
        self.assertGreater(len(data["techniques"]), 0)

        # Search for mimikatz
        sw_res = self.client.get("/api/search?q=mimikatz")
        self.assertEqual(sw_res.status_code, 200)
        sw_data = sw_res.json()
        self.assertGreater(len(sw_data["software"]), 0)


if __name__ == "__main__":
    unittest.main()
