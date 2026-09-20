import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.mitre.db import MitreRepository


def format_technique(detail):
    t = detail.technique
    lines = [
        f"\n{'='*75}",
        f" ATT&CK Technique: [{t.attack_id}] {t.name}",
        f"{'='*75}",
        f"  * URL:            {t.url or 'N/A'}",
        f"  * Sub-technique:  {'Yes (Parent: ' + (t.parent_attack_id or 'None') + ')' if t.is_subtechnique else 'No'}",
        f"  * Tactics:        {', '.join(t.tactics) if t.tactics else 'None'}",
        f"  * Platforms:      {', '.join(t.platforms) if t.platforms else 'None'}",
        f"\n[Description]",
        f"  {t.description[:400] + '...' if len(t.description) > 400 else t.description}",
    ]

    if detail.subtechniques:
        lines.append(f"\n[Sub-techniques ({len(detail.subtechniques)})]")
        for st in detail.subtechniques[:10]:
            lines.append(f"  - [{st.attack_id}] {st.name}")
        if len(detail.subtechniques) > 10:
            lines.append(f"    ... and {len(detail.subtechniques) - 10} more")

    if detail.mitigations:
        lines.append(f"\n[Mitigations / Defensive Controls ({len(detail.mitigations)})]")
        for m in detail.mitigations:
            lines.append(f"  - [{m.attack_id}] {m.name}")

    if detail.groups:
        lines.append(f"\n[Threat Groups Known to Use ({len(detail.groups)})]")
        grp_names = [f"[{g.attack_id}] {g.name}" for g in detail.groups[:8]]
        lines.append(f"  {', '.join(grp_names)}")
        if len(detail.groups) > 8:
            lines.append(f"  ... and {len(detail.groups) - 8} more groups")

    if detail.software:
        lines.append(f"\n[Associated Software & Malware ({len(detail.software)})]")
        sw_names = [s.name for s in detail.software[:10]]
        lines.append(f"  {', '.join(sw_names)}")
        if len(detail.software) > 10:
            lines.append(f"  ... and {len(detail.software) - 10} more tools")

    lines.append("=" * 75)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Cypher AI - MITRE ATT&CK CLI Inspector")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Command: get <attack_id>
    get_parser = subparsers.add_parser("get", help="Get full details for a technique by ATT&CK ID")
    get_parser.add_argument("attack_id", help="e.g. T1059 or T1059.001")

    # Command: list-tactics
    subparsers.add_parser("list-tactics", help="List all 14 Enterprise tactics")

    # Command: list-by-tactic <tactic>
    tactic_parser = subparsers.add_parser("by-tactic", help="List techniques belonging to a tactic")
    tactic_parser.add_argument("tactic", help="e.g. initial-access, execution, defense-evasion")

    # Command: search <term>
    search_parser = subparsers.add_parser("search", help="Search techniques by ID or name keyword")
    search_parser.add_argument("query", help="Keyword or ID substring")

    # Command: stats
    subparsers.add_parser("stats", help="Show database record counts")

    args = parser.parse_args()

    repo = MitreRepository()
    try:
        if args.command == "get":
            detail = repo.get_technique(args.attack_id)
            if not detail:
                print(f"[!] Technique with ID '{args.attack_id}' not found.")
            else:
                print(format_technique(detail))

        elif args.command == "list-tactics":
            tactics = repo.list_tactics()
            print("\n=== MITRE Enterprise ATT&CK Tactics ===")
            for t in tactics:
                print(f"[{t.attack_id}] {t.name:<25} ({t.shortname})")

        elif args.command == "by-tactic":
            techs = repo.get_techniques_by_tactic(args.tactic)
            print(f"\n=== Techniques for Tactic '{args.tactic}' ({len(techs)} found) ===")
            for t in techs:
                prefix = "  |-- " if t.is_subtechnique else "* "
                print(f"{prefix}[{t.attack_id}] {t.name}")

        elif args.command == "search":
            results = repo.search_techniques(args.query)
            print(f"\n=== Search results for '{args.query}' ({len(results)} found) ===")
            for t in results:
                print(f"* [{t.attack_id}] {t.name} ({', '.join(t.platforms) if t.platforms else 'Any'})")

        elif args.command == "stats":
            stats = repo.get_statistics()
            print("\n=== MITRE ATT&CK Database Statistics ===")
            for k, v in stats.items():
                print(f"  - {k:30s}: {v:,}")

        else:
            parser.print_help()

    finally:
        repo.close()


if __name__ == "__main__":
    main()
