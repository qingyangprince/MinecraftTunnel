from __future__ import annotations

import threading
import unittest

from minecraft_tunnel.stats import (
    TunnelStats,
    format_bytes,
    format_duration,
)


class FormatTests(unittest.TestCase):
    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1023), "1023 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1536), "1.5 KB")
        self.assertEqual(format_bytes(1024**2), "1.0 MB")

    def test_format_duration(self) -> None:
        self.assertEqual(format_duration(0), "00:00:00")
        self.assertEqual(format_duration(59), "00:00:59")
        self.assertEqual(format_duration(3661), "01:01:01")


class TunnelStatsTests(unittest.TestCase):
    def test_counters(self) -> None:
        stats = TunnelStats()
        self.assertEqual(stats.connection_opened(), 1)
        self.assertEqual(stats.connection_opened(), 2)
        stats.connection_closed()
        stats.add_up(100)
        stats.add_down(200)
        stats.add_up(50)

        snapshot = stats.snapshot()
        self.assertEqual(snapshot.active_connections, 1)
        self.assertEqual(snapshot.total_connections, 2)
        self.assertEqual(snapshot.bytes_up, 150)
        self.assertEqual(snapshot.bytes_down, 200)
        self.assertGreaterEqual(snapshot.uptime, 0)

    def test_close_never_goes_negative(self) -> None:
        stats = TunnelStats()
        stats.connection_closed()
        self.assertEqual(stats.snapshot().active_connections, 0)

    def test_thread_safe_updates(self) -> None:
        stats = TunnelStats()

        def worker() -> None:
            for _ in range(1000):
                stats.add_up(1)
                stats.add_down(1)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        snapshot = stats.snapshot()
        self.assertEqual(snapshot.bytes_up, 4000)
        self.assertEqual(snapshot.bytes_down, 4000)


if __name__ == "__main__":
    unittest.main()
