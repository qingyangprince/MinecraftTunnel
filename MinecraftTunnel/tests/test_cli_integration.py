from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.helpers import EchoServer, free_port

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(min(remaining, 64 * 1024))
        if not chunk:
            raise AssertionError(f"连接提前关闭，剩余 {remaining} 字节")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class CliIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.config_path = Path(self._temp_dir.name) / "config.json"

        self.echo = EchoServer()
        self.echo.start()
        self.addCleanup(self.echo.close)

        self.env = os.environ.copy()
        self.env["MC_TUNNEL_CONFIG"] = str(self.config_path)
        self.env["PYTHONUNBUFFERED"] = "1"

    def _start_cli(self, *args: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "main.py"), *args],
            cwd=PROJECT_ROOT,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        self.addCleanup(self._stop_cli, process)
        return process

    @staticmethod
    def _stop_cli(process: subprocess.Popen[str]) -> tuple[str, str]:
        if process.poll() is None:
            process.terminate()
        try:
            return process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.communicate(timeout=5)

    def _wait_for_port(self, port: int, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.05)
        self.fail(f"端口 {port} 在 {timeout} 秒内没有开始监听")

    def _assert_echo(self, port: int, payload: bytes) -> None:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
            sock.settimeout(3.0)
            sock.sendall(payload)
            self.assertEqual(_recv_exact(sock, len(payload)), payload)

    def _wait_for_config(self) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.config_path.exists():
                return
            time.sleep(0.05)
        self.fail("配置文件没有生成")

    def test_host_and_join_subprocesses(self) -> None:
        host_port = free_port()
        host = self._start_cli(
            "host",
            "-p",
            str(host_port),
            "-t",
            f"127.0.0.1:{self.echo.port}",
            "--no-upnp",
            "--stats-interval",
            "0",
        )
        self._wait_for_port(host_port)
        self._assert_echo(host_port, b"host-ping")

        self._wait_for_config()
        saved = json.loads(self.config_path.read_text(encoding="utf-8"))
        self.assertEqual(saved["last_port"], host_port)
        self.assertEqual(saved["local_server"], f"127.0.0.1:{self.echo.port}")

        self._stop_cli(host)
        self.assertIsNotNone(host.poll())

        join_port = free_port()
        while join_port == host_port:
            join_port = free_port()

        join = self._start_cli(
            "join",
            "-H",
            "127.0.0.1",
            "-p",
            str(self.echo.port),
            "-l",
            str(join_port),
            "--no-check",
            "--stats-interval",
            "0",
        )
        self._wait_for_port(join_port)
        self._assert_echo(join_port, b"join-ping")

        deadline = time.monotonic() + 5.0
        while True:
            saved = json.loads(self.config_path.read_text(encoding="utf-8"))
            if saved.get("local_listen_port") == join_port:
                break
            if time.monotonic() >= deadline:
                self.fail("加入模式的配置没有写入")
            time.sleep(0.05)

        self.assertEqual(saved["last_host"], "127.0.0.1")
        self.assertEqual(saved["last_remote_port"], self.echo.port)
        self.assertEqual(saved["local_listen_port"], join_port)

        self._stop_cli(join)


if __name__ == "__main__":
    unittest.main()
