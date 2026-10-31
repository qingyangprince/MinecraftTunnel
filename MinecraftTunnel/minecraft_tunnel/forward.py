"""TCP 端口转发核心。

Minecraft Java 版的联机流量是普通 TCP 字节流，因此这里不做任何协议解析，
只负责把客户端连接原样转发到目标地址。这样既不会破坏 Minecraft 协议，
也能同时支持多个玩家。
"""

from __future__ import annotations

import errno
import logging
import os
import socket
import threading
import time

from .stats import TunnelStats

logger = logging.getLogger(__name__)

BUFFER_SIZE = 64 * 1024
DEFAULT_BACKLOG = 64
DEFAULT_CONNECT_TIMEOUT = 5.0
ACCEPT_POLL_INTERVAL = 0.5
STOP_JOIN_TIMEOUT = 2.0


class TunnelError(RuntimeError):
    """转发器无法启动。"""


class TcpForwarder:
    """监听一个本地端口，并把每条连接转发到目标地址。"""

    def __init__(
        self,
        *,
        listen_host: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        name: str = "tunnel",
        backlog: int = DEFAULT_BACKLOG,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        stats: TunnelStats | None = None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.name = name
        self.backlog = backlog
        self.connect_timeout = connect_timeout
        self.stats = stats or TunnelStats()

        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sessions_lock = threading.Lock()
        self._sessions: set[socket.socket] = set()
        self._session_threads: set[threading.Thread] = set()
        self._started = False
        self._bound_port: int | None = None

    @property
    def bound_port(self) -> int:
        """实际监听端口；使用 0 让系统分配端口时很有用。"""

        return self._bound_port if self._bound_port is not None else self.listen_port

    @property
    def is_running(self) -> bool:
        thread = self._accept_thread
        return bool(
            self._started
            and thread is not None
            and thread.is_alive()
            and not self._stop_event.is_set()
        )

    def start(self) -> None:
        if self._started:
            raise TunnelError("转发器已经启动，不能重复启动")

        family = socket.AF_INET6 if ":" in self.listen_host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            # Windows 的 SO_REUSEADDR 会允许“抢占”已占用的端口，
            # 反而让端口冲突检测失效；因此只在 POSIX 上开启。
            if os.name != "nt":
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.listen_host, self.listen_port))
            listener.listen(self.backlog)
            listener.settimeout(ACCEPT_POLL_INTERVAL)
        except OSError as exc:
            listener.close()
            raise TunnelError(self._bind_error(exc)) from exc

        self._listener = listener
        self._bound_port = listener.getsockname()[1]
        self._started = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"{self.name}-accept",
            daemon=True,
        )
        self._accept_thread.start()

        logger.info(
            "转发已启动：%s:%d -> %s:%d",
            self.listen_host,
            self.bound_port,
            self.target_host,
            self.target_port,
        )

    def wait(self) -> None:
        """阻塞到转发器停止（通常由 Ctrl+C 触发）。"""

        while not self._stop_event.is_set():
            thread = self._accept_thread
            if thread is None or not thread.is_alive():
                break
            self._stop_event.wait(ACCEPT_POLL_INTERVAL)

    def stop(self) -> None:
        """停止监听并关闭所有活动连接，可重复调用。"""

        if self._stop_event.is_set() and self._listener is None:
            return

        self._stop_event.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            self._close_socket(listener, abort=False)

        with self._sessions_lock:
            sessions = list(self._sessions)
        for session in sessions:
            self._close_socket(session, abort=True)

        accept_thread = self._accept_thread
        if (
            accept_thread is not None
            and accept_thread.is_alive()
            and accept_thread is not threading.current_thread()
        ):
            accept_thread.join(timeout=STOP_JOIN_TIMEOUT)

        with self._sessions_lock:
            session_threads = list(self._session_threads)
        deadline = time.monotonic() + STOP_JOIN_TIMEOUT
        for thread in session_threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=remaining)

        logger.info("转发已停止")

    def __enter__(self) -> TcpForwarder:  # noqa: PYI034
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # 监听与连接处理
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        listener = self._listener
        if listener is None:  # pragma: no cover - 仅防御性检查
            return

        consecutive_errors = 0
        try:
            while not self._stop_event.is_set():
                try:
                    client, address = listener.accept()
                except TimeoutError:
                    continue
                except OSError as exc:
                    if self._stop_event.is_set():
                        break
                    consecutive_errors += 1
                    logger.error("接受连接失败：%s", exc)
                    if consecutive_errors >= 5:
                        logger.error("连续接受连接失败，转发器停止")
                        break
                    self._stop_event.wait(0.2)
                    continue

                consecutive_errors = 0
                client.settimeout(None)
                self._configure_socket(client)
                peer = f"{address[0]}:{address[1]}"
                session_id = self.stats.connection_opened()
                self._register(client)
                logger.info("连接 #%d 来自 %s", session_id, peer)

                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client, peer, session_id),
                    name=f"{self.name}-session-{session_id}",
                    daemon=True,
                )
                with self._sessions_lock:
                    self._session_threads.add(thread)
                thread.start()
        finally:
            self._stop_event.set()

    def _handle_client(self, client: socket.socket, peer: str, session_id: int) -> None:
        upstream: socket.socket | None = None
        try:
            if self._stop_event.is_set():
                return

            upstream = socket.create_connection(
                (self.target_host, self.target_port),
                timeout=self.connect_timeout,
            )
            upstream.settimeout(None)
            self._configure_socket(upstream)
            self._register(upstream)

            logger.info(
                "连接 #%d 已建立：%s -> %s:%d",
                session_id,
                peer,
                self.target_host,
                self.target_port,
            )
            self._relay(client, upstream)
        except OSError as exc:
            if not self._stop_event.is_set():
                logger.warning(
                    "连接 #%d 无法转发到 %s:%d：%s",
                    session_id,
                    self.target_host,
                    self.target_port,
                    exc,
                )
        except Exception:  # pragma: no cover - 防止单条连接拖垮整个进程
            logger.exception("连接 #%d 处理时发生未预期错误", session_id)
        finally:
            self._unregister(upstream)
            self._close_socket(upstream, abort=False)
            self._unregister(client)
            self._close_socket(client, abort=False)
            self.stats.connection_closed()
            with self._sessions_lock:
                self._session_threads.discard(threading.current_thread())
            logger.info("连接 #%d 已关闭", session_id)

    def _relay(self, client: socket.socket, upstream: socket.socket) -> None:
        """在客户端和目标之间做双向复制。"""

        up_thread = threading.Thread(
            target=self._pump,
            args=(client, upstream, True),
            name=f"{self.name}-up",
            daemon=True,
        )
        down_thread = threading.Thread(
            target=self._pump,
            args=(upstream, client, False),
            name=f"{self.name}-down",
            daemon=True,
        )
        up_thread.start()
        down_thread.start()

        up_thread.join()
        down_thread.join()

    def _pump(
        self, source: socket.socket, destination: socket.socket, is_up: bool
    ) -> None:
        aborted = False
        try:
            while not self._stop_event.is_set():
                data = source.recv(BUFFER_SIZE)
                if not data:
                    break
                destination.sendall(data)
                if is_up:
                    self.stats.add_up(len(data))
                else:
                    self.stats.add_down(len(data))
        except OSError as exc:
            aborted = not self._stop_event.is_set()
            if aborted:
                logger.debug("连接转发中断：%s", exc)
        finally:
            # 半关闭：把“读完了”传给另一端，让对端有机会正常收尾。
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

            if aborted and not self._stop_event.is_set():
                for sock in (source, destination):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    # ------------------------------------------------------------------
    # 小工具
    # ------------------------------------------------------------------

    def _register(self, sock: socket.socket) -> None:
        with self._sessions_lock:
            self._sessions.add(sock)

    def _unregister(self, sock: socket.socket | None) -> None:
        if sock is None:
            return
        with self._sessions_lock:
            self._sessions.discard(sock)

    @staticmethod
    def _configure_socket(sock: socket.socket) -> None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass

    @staticmethod
    def _close_socket(sock: socket.socket | None, *, abort: bool) -> None:
        if sock is None:
            return
        if abort:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        try:
            sock.close()
        except OSError:
            pass

    def _bind_error(self, exc: OSError) -> str:
        code = getattr(exc, "winerror", None) or exc.errno
        if code in (errno.EADDRINUSE, 10048):
            return (
                f"端口 {self.listen_port} 已被占用，请换一个端口"
                "（可能是另一个联机工具或 Minecraft 服务端）"
            )
        if code in (errno.EACCES, 10013):
            return (
                f"没有权限监听端口 {self.listen_port}；"
                "请改用 1024 以上的端口，或以管理员身份运行"
            )
        if code in (errno.EADDRNOTAVAIL, 10049):
            return f"监听地址 {self.listen_host} 在本机不存在"
        detail = exc.strerror or str(exc)
        return f"无法监听 {self.listen_host}:{self.listen_port}：{detail}"
