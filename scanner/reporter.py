"""
reporter.py — Format and output scan results as JSON or plain text.

Keeping output logic separate from scanning logic means you can add new
output formats (CSV, XML, HTML) without touching the scanner itself.
"""

import json
import sys
from datetime import datetime, timezone


def build_report(
    host: str,
    ports_scanned: int,
    duration: float,
    results: list[dict],
) -> dict:
    """
    Assemble a structured report dict from raw scan results.

    Args:
        host:          Target that was scanned.
        ports_scanned: Total number of ports attempted.
        duration:      Elapsed scan time in seconds.
        results:       List of result dicts from core.py / banner.py.

    Returns:
        A report dict ready for JSON serialization or text rendering.
    """
    open_ports = [r for r in results if r.get("state") == "open"]

    return {
        "meta": {
            "target":        host,
            "scanned_at":    datetime.now(timezone.utc).isoformat(),
            "ports_scanned": ports_scanned,
            "duration_sec":  round(duration, 2),
            "open_count":    len(open_ports),
        },
        "results": results,
    }


def output_json(report: dict, filepath: str | None = None) -> None:
    """
    Write the report as indented JSON.

    Args:
        report:   Report dict from build_report().
        filepath: If given, write to this file path. Otherwise print to stdout.
    """
    serialized = json.dumps(report, indent=2)

    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(serialized)
        print(f"[+] JSON report saved to: {filepath}")
    else:
        print(serialized)


def output_text(report: dict, filepath: str | None = None) -> None:
    """
    Write the report as human-readable plain text.

    Args:
        report:   Report dict from build_report().
        filepath: If given, write to this file path. Otherwise print to stdout.
    """
    meta = report["meta"]
    results = report["results"]
    open_ports = [r for r in results if r.get("state") == "open"]

    lines = []
    lines.append("=" * 60)
    lines.append(f"  Port Scanner Report")
    lines.append("=" * 60)
    lines.append(f"  Target       : {meta['target']}")
    lines.append(f"  Scanned at   : {meta['scanned_at']}")
    lines.append(f"  Ports scanned: {meta['ports_scanned']}")
    lines.append(f"  Duration     : {meta['duration_sec']}s")
    lines.append(f"  Open ports   : {meta['open_count']}")
    lines.append("=" * 60)

    if not open_ports:
        lines.append("  No open ports found.")
    else:
        lines.append(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<15} BANNER")
        lines.append("  " + "-" * 56)
        for r in open_ports:
            banner = r.get("banner") or ""
            # Truncate long banners so lines stay readable
            banner_preview = banner[:40].replace("\r", "").replace("\n", " ") if banner else "-"
            lines.append(
                f"  {r['port']:<8} {r['state']:<10} "
                f"{r.get('service', 'unknown'):<15} {banner_preview}"
            )

    lines.append("=" * 60)

    output = "\n".join(lines)

    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"[+] Text report saved to: {filepath}")
    else:
        print(output)


def write_report(
    report: dict,
    fmt: str = "text",
    filepath: str | None = None,
) -> None:
    """
    Dispatch to the correct output function based on format string.

    Args:
        report:   Report dict from build_report().
        fmt:      'json' or 'text' (default 'text').
        filepath: Optional file path to write to instead of stdout.

    Raises:
        ValueError: If fmt is not a recognized format.
    """
    fmt = fmt.lower().strip()

    if fmt == "json":
        output_json(report, filepath)
    elif fmt == "text":
        output_text(report, filepath)
    else:
        raise ValueError(f"Unknown output format: '{fmt}'. Use 'json' or 'text'.")