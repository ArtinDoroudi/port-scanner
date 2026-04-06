"""
test_scanner.py — Unit tests for the port scanner modules.
"""

import json
import unittest
from unittest.mock import patch, MagicMock

from scanner.core import parse_port_range, scan_port, run_scan
from scanner.banner import identify_service, enrich_result
from scanner.reporter import build_report, output_json, output_text


# ---------------------------------------------------------------------------
# core.py tests
# ---------------------------------------------------------------------------

class TestParsePortRange(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(parse_port_range("80"), [80])

    def test_range(self):
        self.assertEqual(parse_port_range("1-5"), [1, 2, 3, 4, 5])

    def test_comma_list(self):
        self.assertEqual(parse_port_range("22,80,443"), [22, 80, 443])

    def test_mixed(self):
        self.assertEqual(parse_port_range("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_deduplication(self):
        self.assertEqual(parse_port_range("80,80,80"), [80])

    def test_sorted_output(self):
        self.assertEqual(parse_port_range("443,22,80"), [22, 80, 443])

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_port_range("1000-500")  # start > end

    def test_port_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_port_range("99999")

    def test_zero_port(self):
        with self.assertRaises(ValueError):
            parse_port_range("0")


class TestScanPort(unittest.TestCase):

    @patch("scanner.core.socket.socket")
    def test_open_port(self, mock_socket_class):
        """connect_ex returning 0 means connection succeeded — port is open."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        result = scan_port("127.0.0.1", 80)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["port"], 80)

    @patch("scanner.core.socket.socket")
    def test_closed_port(self, mock_socket_class):
        """connect_ex returning non-zero means port is closed."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused errno
        mock_socket_class.return_value = mock_sock

        result = scan_port("127.0.0.1", 9999)
        self.assertEqual(result["state"], "closed")

    @patch("scanner.core.socket.socket")
    def test_filtered_port(self, mock_socket_class):
        """Socket timeout means the port is likely filtered by a firewall."""
        import socket
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout
        mock_socket_class.return_value = mock_sock

        result = scan_port("127.0.0.1", 81)
        self.assertEqual(result["state"], "filtered")

    @patch("scanner.core.socket.socket")
    def test_bad_hostname(self, mock_socket_class):
        """gaierror means DNS resolution failed."""
        import socket
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.gaierror("Name resolution failed")
        mock_socket_class.return_value = mock_sock

        result = scan_port("not.a.real.host", 80)
        self.assertEqual(result["state"], "error")
        self.assertIsNotNone(result["error"])


class TestRunScan(unittest.TestCase):

    @patch("scanner.core.scan_port")
    def test_returns_all_ports(self, mock_scan_port):
        """run_scan should return one result per port requested."""
        mock_scan_port.side_effect = lambda host, port, timeout: {
            "port": port, "state": "closed", "error": None
        }
        results = run_scan("127.0.0.1", [80, 443, 8080])
        self.assertEqual(len(results), 3)

    @patch("scanner.core.scan_port")
    def test_results_sorted_by_port(self, mock_scan_port):
        """Results should always come back sorted by port number."""
        mock_scan_port.side_effect = lambda host, port, timeout: {
            "port": port, "state": "open", "error": None
        }
        results = run_scan("127.0.0.1", [443, 22, 80])
        ports = [r["port"] for r in results]
        self.assertEqual(ports, sorted(ports))

    @patch("scanner.core.scan_port")
    def test_callback_called_for_each_port(self, mock_scan_port):
        """on_result callback should fire once per port."""
        mock_scan_port.side_effect = lambda host, port, timeout: {
            "port": port, "state": "open", "error": None
        }
        callback_results = []
        run_scan("127.0.0.1", [80, 443], on_result=callback_results.append)
        self.assertEqual(len(callback_results), 2)


# ---------------------------------------------------------------------------
# banner.py tests
# ---------------------------------------------------------------------------

class TestIdentifyService(unittest.TestCase):

    def test_known_port_no_banner(self):
        self.assertEqual(identify_service(22, None), "SSH")
        self.assertEqual(identify_service(80, None), "HTTP")
        self.assertEqual(identify_service(3306, None), "MySQL")

    def test_banner_takes_priority(self):
        """Banner content should override port-number guesses."""
        # Port 8080 is HTTP-Alt by port map, but banner says SSH
        result = identify_service(8080, "SSH-2.0-OpenSSH_8.9")
        self.assertEqual(result, "SSH")

    def test_unknown_port_no_banner(self):
        self.assertEqual(identify_service(54321, None), "unknown")

    def test_banner_smtp(self):
        result = identify_service(25, "220 mail.example.com ESMTP")
        self.assertIn(result, ["SMTP", "FTP/SMTP"])

    def test_banner_redis(self):
        result = identify_service(6379, "+PONG Redis server ready")
        self.assertEqual(result, "Redis")


class TestEnrichResult(unittest.TestCase):

    @patch("scanner.banner.grab_banner")
    def test_open_port_gets_enriched(self, mock_grab):
        mock_grab.return_value = "SSH-2.0-OpenSSH_8.9"
        result = {"port": 22, "state": "open", "error": None}
        enriched = enrich_result(result, "127.0.0.1")
        self.assertEqual(enriched["service"], "SSH")
        self.assertEqual(enriched["banner"], "SSH-2.0-OpenSSH_8.9")

    @patch("scanner.banner.grab_banner")
    def test_closed_port_not_probed(self, mock_grab):
        """Banner grabbing should not be attempted on closed ports."""
        result = {"port": 80, "state": "closed", "error": None}
        enrich_result(result, "127.0.0.1")
        mock_grab.assert_not_called()

    @patch("scanner.banner.grab_banner")
    def test_no_banner_returns_none(self, mock_grab):
        mock_grab.return_value = None
        result = {"port": 80, "state": "open", "error": None}
        enriched = enrich_result(result, "127.0.0.1")
        self.assertIsNone(enriched["banner"])


# ---------------------------------------------------------------------------
# reporter.py tests
# ---------------------------------------------------------------------------

class TestBuildReport(unittest.TestCase):

    def _sample_results(self):
        return [
            {"port": 22,  "state": "open",   "service": "SSH",  "banner": "SSH-2.0", "error": None},
            {"port": 80,  "state": "open",   "service": "HTTP", "banner": None,      "error": None},
            {"port": 443, "state": "closed", "service": "HTTPS","banner": None,      "error": None},
        ]

    def test_meta_fields_present(self):
        report = build_report("127.0.0.1", 3, 1.23, self._sample_results())
        meta = report["meta"]
        self.assertEqual(meta["target"], "127.0.0.1")
        self.assertEqual(meta["ports_scanned"], 3)
        self.assertEqual(meta["open_count"], 2)
        self.assertIn("scanned_at", meta)
        self.assertIn("duration_sec", meta)

    def test_results_preserved(self):
        results = self._sample_results()
        report = build_report("127.0.0.1", 3, 1.0, results)
        self.assertEqual(len(report["results"]), 3)

    def test_open_count_accurate(self):
        report = build_report("127.0.0.1", 3, 1.0, self._sample_results())
        self.assertEqual(report["meta"]["open_count"], 2)


class TestOutputJson(unittest.TestCase):

    def test_valid_json_to_stdout(self):
        import io
        from unittest.mock import patch as p

        report = build_report("127.0.0.1", 1, 0.5, [
            {"port": 80, "state": "open", "service": "HTTP", "banner": None, "error": None}
        ])

        with p("builtins.print") as mock_print:
            output_json(report)
            printed = mock_print.call_args[0][0]
            # Should be valid JSON
            parsed = json.loads(printed)
            self.assertIn("meta", parsed)
            self.assertIn("results", parsed)

    def test_json_written_to_file(self, tmp_path=None):
        import tempfile, os
        report = build_report("127.0.0.1", 1, 0.5, [])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp = f.name

        try:
            output_json(report, filepath=tmp)
            with open(tmp) as f:
                parsed = json.load(f)
            self.assertIn("meta", parsed)
        finally:
            os.unlink(tmp)


class TestOutputText(unittest.TestCase):

    def test_text_contains_target(self):
        from io import StringIO
        from unittest.mock import patch as p

        report = build_report("192.168.1.1", 100, 2.5, [
            {"port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0", "error": None}
        ])

        with p("builtins.print") as mock_print:
            output_text(report)
            all_output = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("192.168.1.1", all_output)


if __name__ == "__main__":
    unittest.main()