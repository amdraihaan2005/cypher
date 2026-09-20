import unittest
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from src.search.sparse import SparseSearchEngine, sanitize_fts_query
from src.search.dense import DenseSearchEngine
from src.search.hybrid import HybridSearchEngine
from src.api.app import app


class TestMultiEntitySearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sparse = SparseSearchEngine()
        cls.dense = DenseSearchEngine()
        cls.hybrid = HybridSearchEngine(sparse_engine=cls.sparse, dense_engine=cls.dense)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.hybrid.close()
        cls.client.close()

    def test_sanitize_fts_query(self):
        self.assertEqual(sanitize_fts_query(""), "")
        self.assertIn('"T1059.001"*', sanitize_fts_query("T1059.001"))
        self.assertIn('"powershell"*', sanitize_fts_query("powershell script"))
        self.assertIn('"cozy"*', sanitize_fts_query("cozy bear"))

    def test_sparse_search_across_entity_types(self):
        # 1. Technique by ID
        t_hits = self.sparse.search("T1059", entity_type="technique", limit=5)
        self.assertGreater(len(t_hits), 0)
        self.assertTrue(all(h[1] == "technique" for h in t_hits))

        # 2. Group by alias (Cozy Bear -> APT29 G0016)
        g_hits = self.sparse.search("Cozy Bear", entity_type="group", limit=5)
        self.assertGreater(len(g_hits), 0)
        self.assertTrue(any(h[0] == "G0016" for h in g_hits))

        # 3. Software by name (Mimikatz -> S0002)
        s_hits = self.sparse.search("Mimikatz", entity_type="software", limit=5)
        self.assertGreater(len(s_hits), 0)
        self.assertTrue(any(h[0] == "S0002" for h in s_hits))

        # 4. Mitigation by name (Multi-factor Authentication -> M1032)
        m_hits = self.sparse.search("Multi-factor Authentication", entity_type="mitigation", limit=5)
        self.assertGreater(len(m_hits), 0)
        self.assertTrue(any(h[0] == "M1032" for h in m_hits))

    def test_dense_semantic_search_intent_groups(self):
        # Natural language query searching for threat actors
        results = self.dense.search("Russian state-sponsored cyber espionage targeting energy and infrastructure", entity_type="group", limit=5)
        self.assertGreater(len(results), 0)
        # Should return APT28 or Sandworm or APT29 in top groups
        ids = [r[0] for r in results]
        self.assertTrue(any(aid in ["G0034", "G0007", "G0016", "G0008", "G1033"] for aid in ids), f"Expected Russian APTs in results, got {ids}")

    def test_dense_semantic_search_intent_techniques(self):
        # Conceptual query for browser credential theft
        results = self.dense.search("stealing saved credentials and session cookies from browser", entity_type="technique", limit=5)
        self.assertGreater(len(results), 0)
        ids = [r[0] for r in results]
        self.assertTrue(any(aid.startswith("T1555") or aid.startswith("T1003") or aid.startswith("T1539") for aid in ids), f"Got {ids}")

    def test_hybrid_search_global_and_filtered(self):
        # Global query: "Mimikatz" should retrieve both software S0002 and techniques using it
        global_hits = self.hybrid.search_hybrid("Mimikatz", limit=5)
        self.assertGreater(len(global_hits), 0)
        types = [h.entity_type for h in global_hits]
        self.assertIn("software", types)

        # Filtered query: group only
        filtered_hits = self.hybrid.search_hybrid("Lazarus bank heist", entity_type="group", limit=3)
        self.assertGreater(len(filtered_hits), 0)
        self.assertTrue(all(h.entity_type == "group" for h in filtered_hits))

    def test_api_search_endpoints_with_entity_type(self):
        # Semantic search with entity_type=group
        res_sem = self.client.get("/api/search/semantic?q=North+Korean+cybercrime+group&entity_type=group&limit=3")
        self.assertEqual(res_sem.status_code, 200)
        data_sem = res_sem.json()
        self.assertEqual(data_sem["mode"], "semantic")
        self.assertEqual(data_sem["entity_type"], "group")
        self.assertGreater(len(data_sem["results"]), 0)

        # Sparse search with entity_type=software
        res_sp = self.client.get("/api/search/sparse?q=Cobalt+Strike&entity_type=software&limit=3")
        self.assertEqual(res_sp.status_code, 200)
        data_sp = res_sp.json()
        self.assertEqual(data_sp["mode"], "sparse")
        self.assertTrue(any(r["entity_id"] == "S0154" for r in data_sp["results"]))

        # Hybrid search with entity_type=mitigation
        res_hyb = self.client.get("/api/search/hybrid?q=password+management+and+mfa&entity_type=mitigation&limit=3")
        self.assertEqual(res_hyb.status_code, 200)
        data_hyb = res_hyb.json()
        self.assertEqual(data_hyb["mode"], "hybrid")
        self.assertGreater(len(data_hyb["results"]), 0)


if __name__ == "__main__":
    unittest.main()
