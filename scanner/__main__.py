"""
__main__.py — Command-line interface for the port scanner.

Making this __main__.py means the scanner package is executable directly:
    python -m scanner --target 127.0.0.1 --ports 1-1024
"""

import argparse
import sys
import time

from colorama import Fore, Style, init as colorama_init

from scanner.core import parse_port_range, run_scan
from scanner.banner import enrich_result
from scanner.reporter import build_report, write_report
from scanner.core import sanitize_host

colorama_init(autoreset=True)


def print_banner() -> None:
    """Print the tool header."""
    print(Fore.CYAN + Style.BRIGHT + """
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚████║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "  TCP Connect Scanner with Banner Grabbing")
    print(Fore.RED + "  Only scan hosts you own or have explicit permission to scan.\n")


def build_arg_parser() -> argparse.ArgumentParser:
    """
    Define and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="python -m scanner",
        description="Multi-threaded TCP port scanner with banner grabbing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python -m scanner --target 127.0.0.1
  python -m scanner --target 192.168.1.1 --ports 1-1024 --threads 200
  python -m scanner --target example.com --ports 22,80,443 --output json
  python -m scanner --target 10.0.0.1 --ports 1-65535 --threads 500 --save results.json
        """,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target hostname or IP address to scan.",
    )
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Ports to scan. Accepts ranges (1-1024), single (80), or lists (22,80,443). Default: 1-1024",
    )
    parser.add_argument(
        "--threads", "-n",
        type=int,
        default=100,
        help="Number of concurrent threads. Higher = faster but noisier. Default: 100",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port connection timeout in seconds. Default: 1.0",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        dest="rate_limit",
        help="Delay in seconds between launching threads. Slows scan, reduces noise. Default: 0",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["text", "json"],
        default="text",
        help="Output format: 'text' (default) or 'json'.",
    )
    parser.add_argument(
        "--save", "-s",
        default=None,
        metavar="FILEPATH",
        help="Save report to a file instead of printing to stdout.",
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        dest="open_only",
        help="Only show open ports in the report.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        dest="no_banner",
        help="Skip banner grabbing (faster, less info).",
    )

    return parser


def on_result_callback(result: dict, open_only: bool) -> None:
    """
    Print live progress as each port result arrives.

    Args:
        result:    Result dict from scan_port().
        open_only: If True, suppress output for non-open ports.
    """
    state = result["state"]
    port = result["port"]

    if state == "open":
        print(Fore.GREEN + f"  [OPEN]     {port}")
    elif state == "filtered" and not open_only:
        print(Fore.YELLOW + f"  [FILTERED] {port}")


def main() -> None:
    """
    Main entrypoint: parse args, run scan, enrich results, write report.
    """
    print_banner()

    parser = build_arg_parser()
    args = parser.parse_args()

    # Parse and validate port range
    try:
        ports = parse_port_range(args.ports)
    except ValueError as e:
        print(Fore.RED + f"[!] Invalid port specification: {e}")
        sys.exit(1)


    clean_host = sanitize_host(args.target)
    print(Fore.CYAN + f"  Target  : {clean_host}")
    print(Fore.CYAN + f"  Ports   : {args.ports} ({len(ports)} ports)")
    print(Fore.CYAN + f"  Threads : {args.threads}")
    print(Fore.CYAN + f"  Timeout : {args.timeout}s")
    print()

    # Run the scan with live output callback
    start = time.monotonic()
    results = run_scan(
        host=clean_host,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        on_result=lambda r: on_result_callback(r, args.open_only),
    )
    duration = time.monotonic() - start

    print()
    print(Fore.CYAN + f"  Scan complete in {duration:.2f}s")
    print()

    # Enrich open ports with banner data unless --no-banner
    if not args.no_banner:
        open_results = [r for r in results if r["state"] == "open"]
        if open_results:
            print(Fore.CYAN + "  Grabbing banners from open ports...")
            for result in open_results:
                enrich_result(result, args.target, args.timeout)
    else:
        for result in results:
            result["banner"] = None
            result["service"] = "unknown"

    # Filter results if --open-only
    if args.open_only:
        results = [r for r in results if r["state"] == "open"]

    # Build and write the report
    report = build_report(
        host=clean_host,
        ports_scanned=len(ports),
        duration=duration,
        results=results,
    )

    write_report(report, fmt=args.output, filepath=args.save)


if __name__ == "__main__":
    main()