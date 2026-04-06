"""
core.py — TCP connect scanner with multi-threading and rate limiting.

Uses Python's socket library to attempt full TCP connections (connect scan).
Unlike SYN scans, connect scans complete the full three-way handshake, which
means they are detectable but require no special privileges to run.
"""

import socket
import threading
import time
from typing import Callable


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Attempt a TCP connect to host:port.

    A successful connection means the port is open — something is actively
    listening. A refused connection means closed. No response means filtered
    (likely a firewall silently dropping packets).

    Args:
        host:    Target hostname or IP address.
        port:    Port number to scan (1–65535).
        timeout: Seconds to wait before giving up. Lower = faster but more
                 false 'filtered' results on slow networks.

    Returns:
        A dict with keys: port, state ('open' | 'closed' | 'filtered'), error.
    """
    result = {"port": port, "state": "closed", "error": None}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        code = sock.connect_ex((host, port))

        if code == 0:
            result["state"] = "open"
        else:
            result["state"] = "closed"

        sock.close()

    except socket.timeout:
        result["state"] = "filtered"
    except socket.gaierror as e:
        # Host resolution failed — bad hostname or no DNS
        result["state"] = "error"
        result["error"] = str(e)
    except OSError as e:
        result["state"] = "error"
        result["error"] = str(e)

    return result


def parse_port_range(port_range: str) -> list[int]:
    """
    Parse a port range string into a list of integers.

    Accepts:
        "80"         → [80]
        "1-1024"     → [1, 2, ..., 1024]
        "22,80,443"  → [22, 80, 443]

    Args:
        port_range: String representation of ports to scan.

    Returns:
        Sorted list of port numbers.

    Raises:
        ValueError: If the format is invalid or ports are out of range.
    """
    ports = []

    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Invalid port range: {part}")
            ports.extend(range(start, end + 1))
        else:
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port out of range: {port}")
            ports.append(port)

    return sorted(set(ports))


def run_scan(
    host: str,
    ports: list[int],
    threads: int = 100,
    timeout: float = 1.0,
    rate_limit: float = 0.0,
    on_result: Callable[[dict], None] | None = None,
) -> list[dict]:
    """
    Scan a list of ports on host using a thread pool.

    Each port gets its own thread up to the `threads` limit. A semaphore
    controls concurrency so we don't overwhelm the target or exhaust local
    file descriptors.

    Args:
        host:       Target hostname or IP address.
        ports:      List of port numbers to scan.
        threads:    Max concurrent threads (default 100).
        timeout:    Per-port connection timeout in seconds.
        rate_limit: Optional delay (seconds) between launching threads.
                    Useful for staying under IDS thresholds.
        on_result:  Optional callback invoked with each result as it arrives.
                    Useful for live progress output.

    Returns:
        List of result dicts, sorted by port number.
    """
    results = []
    results_lock = threading.Lock()
    semaphore = threading.Semaphore(threads)

    def worker(port: int) -> None:
        with semaphore:
            result = scan_port(host, port, timeout)
            with results_lock:
                results.append(result)
            if on_result:
                on_result(result)

    thread_list = []
    for port in ports:
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        thread_list.append(t)
        t.start()
        if rate_limit > 0:
            time.sleep(rate_limit)

    for t in thread_list:
        t.join()

    return sorted(results, key=lambda r: r["port"])