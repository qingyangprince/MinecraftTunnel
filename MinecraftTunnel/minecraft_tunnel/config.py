"""配置文件的读写与向后兼容。"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .net import DEFAULT_MINECRAFT_PORT, parse_endpoint, validate_port

logger = logging.getLogger(__name__)

CONFIG_FILENAME = "game_net_config.json"
DEFAULT_HOST_PORT = 57575
DEFAULT_REMOTE_PORT = 25565
DEFAULT_LOCAL_SERVER = f"127.0.0.1:{DEFAULT_REMOTE_PORT}"
DEFAULT_LISTEN_PORT = 25566


class ConfigError(RuntimeError):
    """配置文件无法读取或写入。"""


def default_config_path() -> Path:
    """返回配置文件路径。

    优先使用 ``MC_TUNNEL_CONFIG`` 环境变量；源码运行时固定在项目根目录，
    避免从不同工作目录启动时“配置丢失”。通过 wheel 安装且包目录不可写时，
    回退到用户配置目录（Windows 为 ``%APPDATA%``）。
    """

    override = os.environ.get("MC_TUNNEL_CONFIG")
    if override:
        return Path(override).expanduser()

    if getattr(sys, "frozen", False):  # PyInstaller 等打包场景
        return Path(sys.executable).resolve().parent / CONFIG_FILENAME

    project_root = Path(__file__).resolve().parent.parent
    if (project_root / "pyproject.toml").exists() or (
        project_root / "main.py"
    ).exists():
        return project_root / CONFIG_FILENAME

    # 通过 wheel 安装时，包目录通常不可写；放到用户配置目录。
    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home() / ".config"
    return base / "MinecraftTunnel" / CONFIG_FILENAME


@dataclass
class AppConfig:
    """应用配置。

    ``max_players`` 仅为兼容旧配置文件保留，实际人数由 Minecraft 服务端控制。
    """

    last_host: str = ""
    last_port: int = DEFAULT_HOST_PORT
    last_remote_port: int = DEFAULT_REMOTE_PORT
    local_server: str = DEFAULT_LOCAL_SERVER
    local_listen_port: int = DEFAULT_LISTEN_PORT
    enable_upnp: bool = True
    max_players: int = 8

    def to_dict(self) -> dict[str, Any]:
        return {field.name: getattr(self, field.name) for field in fields(self)}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> AppConfig:
        """从任意 JSON 对象构造配置，坏值回退到默认值而不是崩溃。"""

        config = cls()
        config.last_host = _as_host(data.get("last_host"), config.last_host)
        config.last_port = _as_port(data.get("last_port"), config.last_port)
        config.last_remote_port = _as_port(
            data.get("last_remote_port"), config.last_remote_port
        )
        config.local_server = _as_endpoint(
            data.get("local_server"), config.local_server
        )
        config.local_listen_port = _as_port(
            data.get("local_listen_port"), config.local_listen_port
        )
        config.enable_upnp = _as_bool(data.get("enable_upnp"), config.enable_upnp)
        config.max_players = _as_positive_int(
            data.get("max_players"), config.max_players
        )
        return config


class ConfigStore:
    """负责配置文件的加载与原子写入。"""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path is not None else default_config_path()

    def load(self) -> AppConfig:
        if not self.path.exists():
            return AppConfig()

        try:
            raw = self.path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise ConfigError(f"无法读取配置文件 {self.path}：{exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("配置文件格式错误（%s），本次使用默认配置", exc)
            return AppConfig()

        if not isinstance(data, dict):
            logger.warning("配置文件顶层必须是 JSON 对象，本次使用默认配置")
            return AppConfig()

        return AppConfig.from_mapping(data)

    def save(self, config: AppConfig) -> None:
        """原子写入配置，避免进程中断时留下半个文件。"""

        payload = json.dumps(config.to_dict(), ensure_ascii=False, indent=2) + "\n"
        temp_name: str | None = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
            )
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            temp_name = None
        except OSError as exc:
            raise ConfigError(f"无法保存配置文件 {self.path}：{exc}") from exc
        finally:
            if temp_name is not None:
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass


def _as_host(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _as_port(value: Any, default: int) -> int:
    try:
        return validate_port(value)
    except (TypeError, ValueError):
        return default


def _as_endpoint(value: Any, default: str) -> str:
    if value is None:
        return default
    try:
        endpoint = parse_endpoint(str(value), default_port=DEFAULT_MINECRAFT_PORT)
    except (TypeError, ValueError):
        return default
    return str(endpoint)


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "是"}:
            return True
        if normalized in {"0", "false", "no", "off", "否"}:
            return False
    return default


def _as_positive_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default
