import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.search.sparse import SparseSearchEngine
from src.search.dense import DenseSearchEngine


def main():
    start_time = time.time()
    print("=" * 70)
    print(" CYPHER AI - BUILDING HYBRID SEARCH INDEX")
    print("=" * 70)

    # Step 1: Build FTS5 Sparse Index
    print("\n[1/2] Building SQLite FTS5 BM25 Virtual Table...")
    sparse = SparseSearchEngine()
    sparse.build_index()
    print("  -> mitre_entities_fts populated with BM25 index across all 1,757 entities.")
    sparse.close()

    # Step 2: Build Dense Semantic Embeddings
    print("\n[2/2] Generating FastEmbed Semantic Vector Embeddings...")
    dense = DenseSearchEngine()
    dense.build_index()
    print("  -> Dense embeddings saved successfully.")

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f" SEARCH INDEX BUILD COMPLETED in {elapsed:.2f}s!")
    print("=" * 70)


if __name__ == "__main__":
    main()
