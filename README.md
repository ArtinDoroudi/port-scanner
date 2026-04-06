# Port Scanner

A multi-threaded TCP port scanner with banner grabbing and service detection, built in Python.

## Features

- TCP connect scanning across custom port ranges
- Multi-threaded for fast scanning
- Banner grabbing and service fingerprinting
- JSON and plain-text output
- Rate limiting support

## Installation
```bash
git clone https://github.com/ArtinDoroudi/port-scanner.git
cd port-scanner
pip install -r requirements.txt
```

## Usage
```bash
python -m scanner --target 127.0.0.1 --ports 1-1024 --threads 100 --output json
```

## License

MIT