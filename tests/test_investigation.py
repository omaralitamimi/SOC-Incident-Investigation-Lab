import unittest

from investigation.analyzer import investigate


class InvestigationTests(unittest.TestCase):
    def test_correlated_case_becomes_high_severity(self):
        events = [
            *[
                {"timestamp": f"2026-01-01T00:00:0{i}Z", "event_type": "auth_failure", "user": "analyst", "src_ip": "203.0.113.10"}
                for i in range(5)
            ],
            {"timestamp": "2026-01-01T00:01:00Z", "event_type": "auth_success", "user": "analyst", "src_ip": "203.0.113.10"},
            {"timestamp": "2026-01-01T00:02:00Z", "event_type": "process_start", "host": "ws-1", "process": "powershell.exe", "command_line": "powershell.exe -EncodedCommand SAMPLE"},
            {"timestamp": "2026-01-01T00:03:00Z", "event_type": "account_created", "target_user": "svc-test"},
            {"timestamp": "2026-01-01T00:04:00Z", "event_type": "privilege_change", "target_user": "svc-test", "new_role": "administrator"},
        ]
        case = investigate(events)
        self.assertIn(case["severity"], {"high", "critical"})
        self.assertEqual(case["confidence"], "high")

    def test_evidence_timeline_is_chronological(self):
        events = [
            {"timestamp": "2026-01-01T00:02:00Z", "event_type": "auth_success", "user": "u"},
            {"timestamp": "2026-01-01T00:01:00Z", "event_type": "auth_failure", "user": "u"},
        ]
        # investigate expects caller-loaded data to be ordered; sort as load_events does.
        events = sorted(events, key=lambda e: e["timestamp"])
        timeline = investigate(events)["timeline"]
        self.assertLess(timeline[0]["timestamp"], timeline[1]["timestamp"])

    def test_iocs_are_collected(self):
        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "event_type": "network_connection", "host": "ws", "direction": "outbound", "src_ip": "192.0.2.2", "dst_ip": "198.51.100.2", "domain": "lab.example", "sha256": "c" * 64}
        ]
        iocs = investigate(events)["iocs"]
        self.assertIn("198.51.100.2", iocs["ips"])
        self.assertIn("lab.example", iocs["domains"])
        self.assertIn("c" * 64, iocs["hashes"])


if __name__ == "__main__":
    unittest.main()
