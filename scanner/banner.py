"""
banner.py — Banner grabbing and service fingerprinting.

After confirming a port is open, we attempt to read whatever the service
sends immediately on connection (its "banner"), then match it against known
signatures to identify the service. 
"""

import socket


# Known port-to-service mappings as a fallback when banner matching fails.
# Based on IANA assigned port numbers.
COMMON_SERVICES: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Banner signature patterns: if the banner contains any of these substrings
# (case-insensitive), we label it with the corresponding service name.
BANNER_SIGNATURES: list[tuple[str, str]] = [
    ("SSH",       "SSH"),
    ("FTP",       "FTP"),
    ("SMTP",      "SMTP"),
    ("HTTP",      "HTTP"),
    ("POP3",      "POP3"),
    ("IMAP",      "IMAP"),
    ("MySQL",     "MySQL"),
    ("Redis",     "Redis"),
    ("MongoDB",   "MongoDB"),
    ("RDP",       "RDP"),
    ("220",       "FTP/SMTP"),   # 220 is a common greeting code
]


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """
    Connect to host:port and read whatever the service sends first.

    Many services (SSH, FTP, SMTP) announce themselves immediately on
    connection with a version string or greeting — that's the banner.
    HTTP and similar request-response services won't send anything until
    we send a request first, so we also try sending a generic HTTP probe.

    Args:
        host:    Target hostname or IP address.
        port:    Open port to grab banner from.
        timeout: Seconds to wait for data before giving up.

    Returns:
        Decoded banner string, or None if nothing was received.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Some services need a nudge before they respond
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        except OSError:
            pass

        banner = sock.recv(1024)
        sock.close()

        return banner.decode("utf-8", errors="replace").strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def identify_service(port: int, banner: str | None) -> str:
    """
    Guess the service running on a port using banner content and port number.

    Strategy:
      1. If we have a banner, scan it for known signature strings.
      2. Fall back to our COMMON_SERVICES port map.
      3. If nothing matches, return 'unknown'.

    Args:
        port:   Port number the service is running on.
        banner: Raw banner string from grab_banner(), or None.

    Returns:
        Human-readable service name string.
    """
    if banner:
        banner_upper = banner.upper()
        for signature, service_name in BANNER_SIGNATURES:
            if signature.upper() in banner_upper:
                return service_name

    return COMMON_SERVICES.get(port, "unknown")


def enrich_result(result: dict, host: str, timeout: float = 2.0) -> dict:
    """
    Add banner and service info to an open port result dict from core.py.

    Only runs banner grabbing on ports confirmed open — no point probing
    closed or filtered ports.

    Args:
        result:  A result dict from scan_port() with at least 'port' and 'state'.
        host:    Target hostname or IP address.
        timeout: Timeout passed through to grab_banner().

    Returns:
        The same result dict, mutated in place with 'banner' and 'service' keys.
    """
    if result.get("state") == "open":
        banner = grab_banner(host, result["port"], timeout)
        result["banner"] = banner
        result["service"] = identify_service(result["port"], banner)
    else:
        result["banner"] = None
        result["service"] = COMMON_SERVICES.get(result["port"], "unknown")

    return result