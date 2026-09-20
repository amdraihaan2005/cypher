import sys
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.mitre.downloader import download_enterprise_attack
from src.mitre.service import MitreExtractor
from src.mitre.db import get_connection, init_db, populate_db, MitreRepository


def run_ingestion():
    start_time = time.time()
    print("=" * 70)
    print(" CYPHER AI - PHASE 1: MITRE ATT&CK INGESTION PIPELINE")
    print("=" * 70)

    # Step 1: Download / Cache STIX bundle
    print("\n[1/4] Ensuring Enterprise ATT&CK STIX bundle is available...")
    stix_file = download_enterprise_attack()

    # Step 2: Extract STIX objects & relationships
    print("\n[2/4] Parsing and extracting objects via official MitreAttackData...")
    extractor = MitreExtractor(stix_file)
    
    tactics = extractor.extract_tactics()
    print(f"  -> Extracted {len(tactics)} tactics")

    techniques, tech_stix_to_aid = extractor.extract_techniques()
    print(f"  -> Extracted {len(techniques)} techniques & sub-techniques")

    mitigations, mit_stix_to_aid = extractor.extract_mitigations()
    print(f"  -> Extracted {len(mitigations)} mitigations")

    groups, grp_stix_to_aid = extractor.extract_groups()
    print(f"  -> Extracted {len(groups)} adversary groups")

    software, sw_stix_to_aid = extractor.extract_software()
    print(f"  -> Extracted {len(software)} software/malware/tools")

    relationships = extractor.extract_relationships(
        tech_stix_to_aid=tech_stix_to_aid,
        mit_stix_to_aid=mit_stix_to_aid,
        grp_stix_to_aid=grp_stix_to_aid,
        sw_stix_to_aid=sw_stix_to_aid,
    )
    print(f"  -> Extracted {len(relationships['technique_mitigations'])} technique-mitigation links")
    print(f"  -> Extracted {len(relationships['group_techniques'])} group-technique links")
    print(f"  -> Extracted {len(relationships['software_techniques'])} software-technique links")

    # Step 3: Populate SQLite Database
    print("\n[3/4] Initializing and populating SQLite database...")
    conn = get_connection()
    init_db(conn)
    populate_db(
        conn=conn,
        tactics=tactics,
        techniques=techniques,
        mitigations=mitigations,
        groups=groups,
        software=software,
        relationships=relationships,
    )
    conn.close()
    print("  -> Database successfully populated and indexed.")

    # Step 4: Verification & Integrity Checks
    print("\n[4/4] Verifying database integrity and running sample queries...")
    repo = MitreRepository()
    stats = repo.get_statistics()
    print("  Database Table Counts:")
    for table, count in stats.items():
        print(f"    - {table:28s}: {count:,}")

    # Query verification: T1059
    print("\n  Verifying deep query on 'T1059' (Command and Scripting Interpreter):")
    detail = repo.get_technique("T1059")
    if not detail:
        print("  [ERROR] Could not retrieve T1059!")
        sys.exit(1)

    tech = detail.technique
    print(f"    - ID: {tech.attack_id}")
    print(f"    - Name: {tech.name}")
    print(f"    - Tactics: {', '.join(tech.tactics)}")
    print(f"    - Platforms: {', '.join(tech.platforms)}")
    print(f"    - Sub-techniques count: {len(detail.subtechniques)}")
    print(f"    - Mitigations count: {len(detail.mitigations)}")
    print(f"    - Adversary Groups count: {len(detail.groups)}")
    print(f"    - Software/Tools count: {len(detail.software)}")

    # Query verification: T1190 (Exploit Public-Facing Application)
    print("\n  Verifying query on 'T1190' (Exploit Public-Facing Application):")
    detail_1190 = repo.get_technique("T1190")
    if detail_1190:
        print(f"    - ID: {detail_1190.technique.attack_id} ({detail_1190.technique.name})")
        print(f"    - Mitigations ({len(detail_1190.mitigations)}): {', '.join(m.name for m in detail_1190.mitigations[:4])}...")

    repo.close()
    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f" PHASE 1 INGESTION COMPLETED SUCCESSFULLY in {elapsed:.2f}s!")
    print("=" * 70)


if __name__ == "__main__":
    run_ingestion()
