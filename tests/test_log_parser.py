import unittest

from src.horizon_sentinel.log_parser import read_failed_ssh_log
from src.horizon_sentinel.log_parser import parse_failed_ssh_login
from src.horizon_sentinel.detector import detect_repeated_failures
from src.horizon_sentinel.detector import detect_failures_within_window

class TestParseFailedSSHLogin(unittest.TestCase):

    def test_extracts_source_ip_from_failed_login(self):
        log_line = (
            "Oct 27 01:00:10 server01 sshd[1201]: "
            "Failed password for invalid user admin "
            "from 203.0.113.42 port 51001 ssh2"
        )

        result = parse_failed_ssh_login(log_line)

        self.assertEqual(result, "203.0.113.42")

    def test_ignores_successful_login(self):
        log_line = (
            "Oct 27 01:04:45 server01 sshd[1206]: "
            "Accepted password for terran "
            "from 198.51.100.25 port 51005 ssh2"
        )

        result = parse_failed_ssh_login(log_line)

        self.assertIsNone(result)

    def test_handle_malformed_failed_login(self):
        log_line = "Failed password for invalid user admin"

        result = parse_failed_ssh_login(log_line)

        self.assertIsNone(result)

    def test_reads_failed_logins_from_file(self):
        file_path = "data/sample_logs/auth.log"

        result = read_failed_ssh_log(file_path)

        self.assertEqual(len(result), 6)
        self.assertEqual(result.count("203.0.113.42"), 5)
        self.assertEqual(result.count("192.0.2.77"), 1)

    def test_return_empty_list_for_log_without_failures(self):
        file_path = "data/sample_logs/auth.log"

        result = read_failed_ssh_log(file_path)

        self.assertNotIn("198.51.100.25", result)

class TestRepeatedFailureDetection(unittest.TestCase):

    def test_detects_ip_at_threshold(self):
        failed_logins = [
            "203.0.113.42",
            "203.0.113.42",
            "203.0.113.42",
            "203.0.113.42",
            "203.0.113.42",
        ]

        result = detect_repeated_failures(failed_logins)

        self.assertEqual(result, {"203.0.113.42": 5})

    def test_ignores_ip_below_threshold(self):
        failed_logins = [
            "192.0.2.77",
            "192.0.2.77",
        ]

        result = detect_repeated_failures(failed_logins)

        self.assertEqual(result, {})

    def test_counts_multiple_ips_independently(self):
        failed_logins = [
            "203.0.113.42",
            "203.0.113.42",
            "203.0.113.42",
            "203.0.113.42",
            "203.0.113.42",
            "192.0.2.77",
        ]

        result = detect_repeated_failures(failed_logins)

        self.assertEqual(result, {"203.0.113.42": 5})

class TestTimeWindowDetection(unittest.TestCase):

    def test_detects_five_failures_within_five_minutes(self):
        events = [
            {
                "timestamp": f"2026-10-27 01:0{i}:00",
                "source_ip": "203.0.113.42"
            }
            for i in range(5)
        ]

        result = detect_failures_within_window(events)

        self.assertEqual(result, {"203.0.113.42": 5})

    def test_ignores_five_failures_spread_across_nine_minutes(self):
        events = [
            {
                "timestamp": f"2026-10-27 01:{i:02d}:00",
                "source_ip": "203.0.113.42", 
            }
            for i in [0, 1, 2, 3, 5]
        ]

        result = detect_failures_within_window(events)

        self.assertEqual(result, {})

    def test_counts_different_ips_separately(self):
        events = [
            {
                "timestamp": f"2026-10-27 01:0{i}:00",
                "source_ip": "203.0.113.42", 
            }
            for i in range(3)
        ] + [
            {
                "timestamp": f"2026-10-27 01:0{i}:30",
                "source_ip": "192.0.2.77",
            }
            for i in range(3)
        ]

        result = detect_failures_within_window(events)

        self.assertEqual(result, {})

    def test_detects_failures_when_events_are_unsorted(self):
        events = [
            {
                "timestamp": "2026-10-27 01:04:00",
                "source_ip": "203.0.113.42",
            },
            {
                "timestamp": "2026-10-27 01:04:00",
                "source_ip": "203.0.113.42",
            },
            {
                "timestamp": "2026-10-27 01:04:00",
                "source_ip": "203.0.113.42",
            },
            {
                "timestamp": "2026-10-27 01:04:00",
                "source_ip": "203.0.113.42",
            },
            {
                "timestamp": "2026-10-27 01:04:00",
                "source_ip": "203.0.113.42",
            },
        ]

        result = detect_failures_within_window(events)

        self.assertEqual(result, {"203.0.113.42": 5})

    def test_excludes_event_exactly_five_minutes_old(self):
        events = [
            {
                "timestamp": f"2026-10-27 01:{minute:02d}:00",
                "source_ip": "203.0.113.42",
            }
            for minute in [0, 1, 2, 3, 5]
        ]
        
        result = detect_failures_within_window(events)

        self.assertEqual(result, {})

if __name__ == "__main__":
    unittest.main()