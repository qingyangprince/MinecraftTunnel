from __future__ import annotations

import os
import socket
import time
import unittest

from minecraft_tunnel.forward import TcpForwarder, TunnelError
from tests.helpers import EchoServer


class ForwarderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.echo = EchoServer()
        self.echo.start()
        self.addCleanup(self.echo.close)

        self.forwarder = TcpForwarder(
            listen_host="127.0.0.1",
            listen_port=0,
            target_host="127.0.0.1",
            target_port=self.echo.port,
        )
        self.forwarder.start()
        self.addCleanup(self.forwarder.stop)

    def _connect(self) -> socket.socket:
        sock = socket.create_connection(
            ("127.0.0.1", self.forwarder.bound_port), timeout=2.0
        )
        sock.settimeout(5.0)
        self.addCleanup(sock.close)
        return sock

    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = sock.recv(min(remaining, 64 * 1024))
            if not chunk:
                self.fail(f"连接提前关闭，剩余 {remaining} 字节")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _wait_until(self, predicate, timeout: float = 3.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("等待条件超时")

    def test_bound_port_is_real(self) -> None:
        self.assertNotEqual(self.forwarder.bound_port, 0)
        self.assertTrue(self.forwarder.is_running)

    def test_echo_roundtrip(self) -> None:
        payload = b"hello minecraft\n" * 100
        with self._connect() as sock:
            sock.sendall(payload)
            self.assertEqual(self._recv_exact(sock, len(payload)), payload)

    def test_multiple_connections(self) -> None:
        sockets = [self._connect() for _ in range(5)]
        try:
            for index, sock in enumerate(sockets):
                sock.sendall(f"client-{index}".encode())

            for index, sock in enumerate(sockets):
                expected = f"client-{index}".encode()
                self.assertEqual(self._recv_exact(sock, len(expected)), expected)
        finally:
            for sock in sockets:
                sock.close()

    def test_large_payload(self) -> None:
        payload = os.urandom(512 * 1024)
        with self._connect() as sock:
            sock.sendall(payload)
            self.assertEqual(self._recv_exact(sock, len(payload)), payload)

    def test_active_connection_stats(self) -> None:
        sock = self._connect()
        self._wait_until(
            lambda: self.forwarder.stats.snapshot().active_connections == 1
        )
        sock.close()
        self._wait_until(
            lambda: self.forwarder.stats.snapshot().active_connections == 0
        )

    def test_stop_closes_listener(self) -> None:
        port = self.forwarder.bound_port
        self.forwarder.stop()
        self.assertFalse(self.forwarder.is_running)
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1.0)

    def test_start_twice_raises(self) -> None:
        with self.assertRaises(TunnelError):
            self.forwarder.start()

    def test_port_in_use_raises(self) -> None:
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        self.addCleanup(blocker.close)

        forwarder = TcpForwarder(
            listen_host="127.0.0.1",
            listen_port=port,
            target_host="127.0.0.1",
            target_port=self.echo.port,
        )
        with self.assertRaises(TunnelError):
            forwarder.start()

    def test_target_unavailable_closes_client(self) -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        unused_port = probe.getsockname()[1]
        probe.close()

        forwarder = TcpForwarder(
            listen_host="127.0.0.1",
            listen_port=0,
            target_host="127.0.0.1",
            target_port=unused_port,
            connect_timeout=1.0,
        )
        forwarder.start()
        self.addCleanup(forwarder.stop)

        with socket.create_connection(
            ("127.0.0.1", forwarder.bound_port), timeout=2.0
        ) as sock:
            sock.settimeout(3.0)
            sock.sendall(b"hello")
            try:
                data = sock.recv(1024)
            except ConnectionResetError:
                data = b""
            self.assertEqual(data, b"")

        self._wait_until(lambda: forwarder.stats.snapshot().total_connections >= 1)


if __name__ == "__main__":
    unittest.main()
