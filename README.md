# Port Scanner
![Port Scanner Demo](demo2.gif)
![Tests](https://github.com/ArtinDoroudi/port-scanner/actions/workflows/tests.yml/badge.svg)

A multi-threaded TCP port scanner with banner grabbing and service fingerprinting,
built in Python using only the standard library.

I built this to develop a concrete understanding of how services expose themselves
on a network — what a TCP handshake looks like at the socket level, how tools like
Nmap identify running services, and how threading changes the performance profile
of I/O-bound work.

---

## Demo

```
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚████║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚███║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝

  TCP Connect Scanner with Banner Grabbing
  Only scan hosts you own or have explicit permission to scan.

  Target  : scanme.nmap.org
  Ports   : 1-1024 (1024 ports)
  Threads : 100

  [OPEN]     22
  [OPEN]     80

  Scan complete in 1.44s
  Grabbing banners from open ports...

============================================================
  Port Scanner Report
============================================================
  Target       : scanme.nmap.org
  Scanned at   : 2026-04-06T08:11:28.195875+00:00
  Ports scanned: 1024
  Duration     : 1.44s
  Open ports   : 2
============================================================
  PORT     STATE      SERVICE         BANNER
  --------------------------------------------------------
  22       open       SSH             SSH-2.0-OpenSSH_6.6.1p1 Ubuntu
  80       open       HTTP            HTTP/1.1 200 OK
============================================================
```

---

## Installation

```bash
git clone https://github.com/ArtinDoroudi/port-scanner.git
cd port-scanner
pip install -r requirements.txt
```

Requires Python 3.11+. No third-party dependencies beyond `colorama` for terminal colors.

---

## Usage

```bash
# Scan the most common ports
python -m scanner --target 127.0.0.1

# Scan a custom range with JSON output
python -m scanner --target 192.168.1.1 --ports 1-1024 --output json

# Scan specific ports only
python -m scanner --target example.com --ports 22,80,443

# Save results to a file
python -m scanner --target 10.0.0.1 --ports 1-1024 --save results.json

# Faster scan with more threads
python -m scanner --target 192.168.1.1 --ports 1-65535 --threads 500

# Quieter scan with rate limiting (20 attempts/sec)
python -m scanner --target 192.168.1.1 --rate-limit 0.05

# Show open ports only, skip banner grabbing
python -m scanner --target 192.168.1.1 --open-only --no-banner
```

### All options

| Flag | Default | Description |
|---|---|---|
| `--target`, `-t` | required | Hostname or IP to scan |
| `--ports`, `-p` | `1-1024` | Port range: `1-1024`, `80`, or `22,80,443` |
| `--threads`, `-n` | `100` | Concurrent threads |
| `--timeout` | `1.0` | Per-port timeout in seconds |
| `--rate-limit` | `0` | Delay between threads in seconds |
| `--output`, `-o` | `text` | Output format: `text` or `json` |
| `--save`, `-s` | — | Write report to file instead of stdout |
| `--open-only` | — | Only show open ports |
| `--no-banner` | — | Skip banner grabbing |

---

## How it works

This scanner performs **TCP connect scans**. For each port it attempts a full
three-way handshake — SYN, SYN-ACK, ACK. A completed handshake means the port
is open. A RST reply means closed. Silence means filtered (a firewall is dropping
packets).

Threading makes this fast. Port scanning is I/O-bound: the CPU spends almost all
its time waiting for network replies. Python's GIL releases during blocking I/O,
so 100 threads can each be waiting for a response simultaneously — scanning 1,024
ports in ~1.5 seconds instead of ~17 minutes.

Once open ports are identified, the scanner connects again and reads whatever the
service sends first — its banner. SSH announces itself immediately
(`SSH-2.0-OpenSSH_8.9`). HTTP requires a probe request (`HEAD / HTTP/1.0`) to
elicit a response. Banner content is matched against known signatures; if nothing
matches, the port number is looked up in the IANA registry.

**Full technical deep-dive with diagrams:** [artindoroudi.github.io/port-scanner](https://ArtinDoroudi.github.io/port-scanner)

---

## Project structure

```
port-scanner/
├── scanner/
│   ├── __main__.py   # CLI interface (argparse)
│   ├── core.py       # TCP scanning + threading
│   ├── banner.py     # Banner grabbing + service fingerprinting
│   └── reporter.py   # JSON and text output
├── tests/
│   └── test_scanner.py
├── docs/
│   └── index.html    # Technical explainer (GitHub Pages)
├── examples/
│   └── sample_output.json
└── .github/
    └── workflows/
        └── tests.yml
```

---

## Limitations

- TCP connect scans only — no UDP, no SYN (half-open) scan
- No IPv6 support
- Banner grabbing reads only the first 1024 bytes
- Service fingerprinting uses a small signature list, not Nmap's full probe database

---

## Ethical disclaimer

Only scan hosts you own or have explicit written permission to scan.
Unauthorized port scanning may be illegal in your jurisdiction.
This tool is built for learning and authorized security assessment only.

---

## References

- [RFC 793](https://www.rfc-editor.org/rfc/rfc793) — TCP specification
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [IANA Port Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)