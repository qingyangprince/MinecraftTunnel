from __future__ import annotations

import unittest

from minecraft_tunnel.net import (
    Endpoint,
    is_private_ip,
    parse_endpoint,
    validate_port,
)


class ParseEndpointTests(unittest.TestCase):
    def test_host_and_port(self) -> None:
        self.assertEqual(
            parse_endpoint("example.com:25565"), Endpoint("example.com", 25565)
        )

    def test_default_port(self) -> None:
        self.assertEqual(
            parse_endpoint("192.168.1.2", default_port=25565),
            Endpoint("192.168.1.2", 25565),
        )

    def test_ipv6(self) -> None:
        endpoint = parse_endpoint("[::1]:25565")
        self.assertEqual(endpoint, Endpoint("::1", 25565))
        self.assertEqual(str(endpoint), "[::1]:25565")

    def test_hostname_with_port(self) -> None:
        self.assertEqual(
            parse_endpoint("mc.example.com:57575"), Endpoint("mc.example.com", 57575)
        )

    def test_invalid_values(self) -> None:
        for value in (
            "",
            "   ",
            "example.com",
            "::1",
            "[::1",
            "[::1]x",
            "host:not-a-port",
            "host:70000",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_endpoint(value)


class ValidatePortTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(validate_port("25565"), 25565)
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(65535), 65535)

    def test_zero_only_when_allowed(self) -> None:
        with self.assertRaises(ValueError):
            validate_port(0)
        self.assertEqual(validate_port(0, allow_zero=True), 0)

    def test_invalid(self) -> None:
        for value in ("abc", -1, 65536, True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_port(value)


class PrivateIpTests(unittest.TestCase):
    def test_private(self) -> None:
        self.assertTrue(is_private_ip("192.168.1.5"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("127.0.0.1"))

    def test_public_or_domain(self) -> None:
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("example.com"))


if __name__ == "__main__":
    unittest.main()
