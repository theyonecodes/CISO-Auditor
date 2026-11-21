#!/usr/bin/env python3
"""
CISO-Auditor v2.0 — Plugin-based Windows Security Audit
Main entry point with MCP JSON output support.
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from checks import AuditorEngine, WindowsProbe


def run_audit(
    manifest_path: str = None,
    category: str = None,
    check_ids: list = None,
    fix_id: int = None,
    output_mcp: bool = False,
    output_json: bool = False,
    output_file: str = None
):
    """Run the security audit with specified options."""

    if manifest_path is None:
        manifest_path = str(Path(__file__).parent / "checks" / "rules_manifest.json")

    print(f"Loading manifest: {manifest_path}")
    probe = WindowsProbe()
    engine = AuditorEngine(probe, manifest_path)

    if check_ids:
        # Run multiple checks
        print(f"Running checks: {check_ids}...")
        for cid in check_ids:
            print(f"  Running check #{cid}...")
            result = engine.run_check(cid)
        results = {cid: engine.results[cid] for cid in check_ids if cid in engine.results}
    elif category:
        # Run category
        print(f"Running category: {category}...")
        results = engine.run_category(category)
    elif fix_id:
        # Apply fix
        print(f"Applying fix for check #{fix_id}...")
        result = engine.fix_check(fix_id)
        print(f"Fix result: {result.fix_result}")
        return
    else:
        # Run all checks
        print("Running all security checks...")
        def progress(current, total, name):
            print(f"  [{current}/{total}] {name}")

        results = engine.run_all(progress_callback=progress)

    # Output results
    if output_mcp:
        output = engine.export_results_mcp()
        output_str = json.dumps(output, indent=2, default=str)
    elif output_json:
        # Simple JSON output
        output_data = {}
        for cid, result in engine.results.items():
            output_data[str(cid)] = {
                "id": result.check_id,
                "status": result.status.value,
                "details": result.details,
                "remediation": result.remediation,
                "auto_fixable": result.auto_fixable
            }
        output_str = json.dumps(output_data, indent=2, default=str)
    else:
        # Human-readable output
        output_str = format_results(results)

    if output_file:
        with open(output_file, "w") as f:
            f.write(output_str)
        print(f"\nResults written to: {output_file}")
    else:
        print(f"\n{output_str}")

    # Print summary
    if not output_mcp and not output_json:
        print_summary(engine)


def format_results(results) -> str:
    """Format results for human-readable output."""
    lines = []
    lines.append("=" * 70)
    lines.append("CISO-AUDITOR SECURITY AUDIT RESULTS")
    lines.append("=" * 70)

    for cid, result in sorted(results.items()):
        status_symbol = {
            "PASS": "[PASS]",
            "FAIL": "[FAIL]",
            "WARNING": "[WARN]",
            "ERROR": "[ERR]",
            "PENDING": "[...]"
        }.get(result.status.value, "[?]")

        lines.append(f"\n{status_symbol} Check #{cid}: {result.details}")
        if result.remediation:
            lines.append(f"    Fix: {result.remediation}")
        if result.auto_fixable:
            lines.append(f"    [AUTO-FIX AVAILABLE]")

    return "\n".join(lines)


def print_summary(engine):
    """Print a summary of the audit results."""
    summary = engine.get_summary()
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total Checks: {summary['total']}")
    print(f"  PASS:      {summary['passed']}")
    print(f"  FAIL:      {summary['failed']}")
    print(f"  WARNING:   {summary['warnings']}")
    print(f"  ERROR:     {summary['errors']}")

    print("\nBy Category:")
    for cat, stats in summary.get("categories", {}).items():
        print(f"  {cat}: {stats['passed']}/{stats['total']} passed")


def main():
    parser = argparse.ArgumentParser(
        description="CISO-Auditor v2.0 - Windows Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                          # Run all checks
  python main.py --mcp-json               # Output MCP-compatible JSON
  python main.py --category "Boot, Firmware & Hardware"
  python main.py --check-id 1
  python main.py --fix-id 20
  python main.py --output-json --output-file results.json
        """
    )

    parser.add_argument(
        "--manifest",
        default=None,
        help="Path to rules manifest JSON (default: checks/rules_manifest.json)"
    )
    parser.add_argument(
        "--category",
        help="Run only checks in this category"
    )
    parser.add_argument(
        "--check-id",
        type=int,
        nargs='+',
        help="Run checks by ID (can specify multiple)"
    )
    parser.add_argument(
        "--fix-id",
        type=int,
        help="Apply auto-fix for a check by ID"
    )
    parser.add_argument(
        "--mcp-json",
        action="store_true",
        help="Output MCP-compatible JSON format"
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Output simple JSON format"
    )
    parser.add_argument(
        "--output-file",
        help="Write output to file instead of stdout"
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks and exit"
    )

    args = parser.parse_args()

    if args.manifest is None:
        args.manifest = str(Path(__file__).parent / "checks" / "rules_manifest.json")

    if args.list_checks:
        # Load manifest and list checks
        import json
        with open(args.manifest) as f:
            manifest = json.load(f)
        print("Available Checks:")
        print("-" * 80)
        for check in manifest.get("checks", []):
            fixable = " [AUTO-FIX]" if check.get("auto_fixable") else ""
            print(f"  #{check['id']:3d} | {check['name']:<45s} | {check['category']:<40s}{fixable}")
        return

    run_audit(
        manifest_path=args.manifest,
        category=args.category,
        check_ids=args.check_id,
        fix_id=args.fix_id,
        output_mcp=args.mcp_json,
        output_json=args.output_json,
        output_file=args.output_file
    )


if __name__ == "__main__":
    main()