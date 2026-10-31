"""运行统计与周期性日志。"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass


def format_bytes(size: int) -> str:
    """把字节数格式化成易读字符串（1024 进制）。"""

    value = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # pragma: no cover - 循环内已返回


def format_duration(seconds: float) -> str:
    """把秒数格式化成 ``HH:MM:SS``。"""

    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


@dataclass(frozen=True)
class StatsSnapshot:
    uptime: float
    active_connections: int
    total_connections: int
    bytes_up: int
    bytes_down: int


class TunnelStats:
    """线程安全的累计统计。

    ``bytes_up`` 表示玩家 -> Minecraft 服务端，``bytes_down`` 反之。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = time.monotonic()
        self._active_connections = 0
        self._total_connections = 0
        self._bytes_up = 0
        self._bytes_down = 0

    def connection_opened(self) -> int:
        with self._lock:
            self._active_connections += 1
            self._total_connections += 1
            return self._total_connections

    def connection_closed(self) -> None:
        with self._lock:
            if self._active_connections > 0:
                self._active_connections -= 1

    def add_up(self, count: int) -> None:
        with self._lock:
            self._bytes_up += count

    def add_down(self, count: int) -> None:
        with self._lock:
            self._bytes_down += count

    def snapshot(self) -> StatsSnapshot:
        with self._lock:
            return StatsSnapshot(
                uptime=time.monotonic() - self._started_at,
                active_connections=self._active_connections,
                total_connections=self._total_connections,
                bytes_up=self._bytes_up,
                bytes_down=self._bytes_down,
            )


class StatsReporter:
    """后台线程，按固定间隔把统计写进日志。"""

    def __init__(
        self,
        stats: TunnelStats,
        interval: float = 30.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.stats = stats
        self.interval = max(1.0, float(interval))
        self.logger = logger or logging.getLogger("minecraft_tunnel.stats")
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name="stats-reporter", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval):
            snapshot = self.stats.snapshot()
            self.logger.info(
                "运行 %s | 在线连接 %d | 累计连接 %d | 上行 %s | 下行 %s",
                format_duration(snapshot.uptime),
                snapshot.active_connections,
                snapshot.total_connections,
                format_bytes(snapshot.bytes_up),
                format_bytes(snapshot.bytes_down),
            )
