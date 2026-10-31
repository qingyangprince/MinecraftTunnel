"""日志初始化：终端友好、可选颜色。"""

from __future__ import annotations

import logging
import os
import sys

_RESET = "\033[0m"
_DIM = "\033[2m"
_COLORS = {
    logging.DEBUG: "\033[2m",
    logging.INFO: "\033[0m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
    logging.CRITICAL: "\033[1;31m",
}
_LABELS = {
    logging.DEBUG: "调试",
    logging.INFO: "",
    logging.WARNING: "警告",
    logging.ERROR: "错误",
    logging.CRITICAL: "严重",
}


def _enable_windows_vt() -> bool:
    """在传统 Windows 控制台里启用 ANSI 转义序列。"""

    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-12)  # STDERR
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # noqa: BLE001  # pragma: no cover - 仅 Windows 控制台兼容逻辑
        return False


def _supports_color(stream: object) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not getattr(stream, "isatty", lambda: False)():
        return False
    return _enable_windows_vt()


class _ConsoleFormatter(logging.Formatter):
    def __init__(self, *, use_color: bool) -> None:
        super().__init__(datefmt="%H:%M:%S")
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, self.datefmt)
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"

        label = _LABELS.get(record.levelno, record.levelname)
        prefix = f"[{label}] " if label else ""

        if not self.use_color:
            return f"[{timestamp}] {prefix}{message}"

        color = _COLORS.get(record.levelno, "")
        return f"{_DIM}[{timestamp}]{_RESET} {color}{prefix}{message}{_RESET}"


def setup_logging(verbose: bool = False) -> None:
    """配置根日志器。重复调用会替换之前的处理器。"""

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_ConsoleFormatter(use_color=_supports_color(sys.stderr)))
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
