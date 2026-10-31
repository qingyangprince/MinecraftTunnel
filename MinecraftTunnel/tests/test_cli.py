from __future__ import annotations

import contextlib
import io
import unittest

from minecraft_tunnel.cli import _apply_setting, _parse_bool, build_parser
from minecraft_tunnel.config import AppConfig


class ParserTests(unittest.TestCase):
    def test_host_defaults(self) -> None:
        args = build_parser().parse_args(["host"])
        self.assertIsNone(args.port)
        self.assertEqual(args.bind, "0.0.0.0")
        self.assertFalse(args.no_upnp)
        self.assertEqual(args.stats_interval, 30)

    def test_join_defaults(self) -> None:
        args = build_parser().parse_args(["join", "-H", "1.2.3.4"])
        self.assertEqual(args.host, "1.2.3.4")
        self.assertIsNone(args.port)
        self.assertEqual(args.bind, "127.0.0.1")
        self.assertFalse(args.no_check)

    def test_port_validation(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_parser().parse_args(["host", "-p", "99999"])

    def test_verbose_before_and_after_subcommand(self) -> None:
        self.assertTrue(build_parser().parse_args(["-v", "host"]).verbose)
        self.assertTrue(build_parser().parse_args(["host", "-v"]).verbose)
        self.assertFalse(build_parser().parse_args(["host"]).verbose)


class SettingTests(unittest.TestCase):
    def test_parse_bool(self) -> None:
        for value in ("true", "1", "yes", "on", "是", "开"):
            self.assertTrue(_parse_bool(value))
        for value in ("false", "0", "no", "off", "否", "关"):
            self.assertFalse(_parse_bool(value))
        with self.assertRaises(ValueError):
            _parse_bool("maybe")

    def test_apply_local_server(self) -> None:
        config = _apply_setting(AppConfig(), "local_server", "127.0.0.1:25566")
        self.assertEqual(config.local_server, "127.0.0.1:25566")

    def test_apply_local_server_without_port(self) -> None:
        config = _apply_setting(AppConfig(), "local_server", "localhost")
        self.assertEqual(config.local_server, "localhost:25565")

    def test_apply_enable_upnp(self) -> None:
        config = _apply_setting(AppConfig(enable_upnp=True), "enable_upnp", "false")
        self.assertFalse(config.enable_upnp)

    def test_apply_last_remote_port(self) -> None:
        config = _apply_setting(AppConfig(), "last_remote_port", "57575")
        self.assertEqual(config.last_remote_port, 57575)

    def test_apply_invalid_key(self) -> None:
        with self.assertRaises(ValueError):
            _apply_setting(AppConfig(), "unknown", "x")

    def test_apply_invalid_value(self) -> None:
        with self.assertRaises(ValueError):
            _apply_setting(AppConfig(), "local_listen_port", "70000")


if __name__ == "__main__":
    unittest.main()
