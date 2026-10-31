"""测试辅助工具。"""

from __future__ import annotations

import socket
import threading


class EchoServer:
    """测试用的 TCP echo 服务，每条连接一个线程。"""

    def __init__(self) -> None:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]

        self._stop_event = threading.Event()
        self._clients: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        try:
            self._listener.close()
        except OSError:
            pass

        with self._lock:
            clients = list(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass

        if self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                client, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self._clients.add(client)
            threading.Thread(target=self._echo, args=(client,), daemon=True).start()

    def _echo(self, client: socket.socket) -> None:
        try:
            with client:
                while True:
                    data = client.recv(64 * 1024)
                    if not data:
                        return
                    client.sendall(data)
        except OSError:
            pass
        finally:
            with self._lock:
                self._clients.discard(client)


def free_port() -> int:
    """让系统分配一个当前空闲的端口。"""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
