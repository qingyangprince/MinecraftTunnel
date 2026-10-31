"""可选的 UPnP 自动端口映射。

``miniupnpc`` 不是硬依赖；没安装时只提示用户手动做端口转发。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .net import get_local_ip

logger = logging.getLogger(__name__)


class UpnpError(RuntimeError):
    """UPnP 发现或端口映射失败。"""


@dataclass(frozen=True)
class UpnpMapping:
    external_ip: str
    local_ip: str
    port: int
    protocol: str


class UpnpMapper:
    """管理一组 UPnP 端口映射，并在退出时清理。"""

    def __init__(self) -> None:
        self._upnp = None
        self._mappings: list[tuple[int, str]] = []

    @staticmethod
    def available() -> bool:
        try:
            import miniupnpc  # noqa: F401
        except ImportError:
            return False
        return True

    def map_port(
        self,
        port: int,
        *,
        protocol: str = "TCP",
        description: str = "Minecraft Tunnel",
    ) -> UpnpMapping:
        try:
            import miniupnpc
        except ImportError as exc:
            raise UpnpError(
                "未安装 miniupnpc，无法自动映射端口；"
                "可执行 pip install miniupnpc，或手动在路由器上转发"
            ) from exc

        protocol = protocol.upper()
        try:
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 2000
            if upnp.discover() == 0:
                raise UpnpError("没有发现支持 UPnP 的路由器")
            upnp.selectigd()

            local_ip = getattr(upnp, "lanaddr", "") or get_local_ip()
            try:
                external_ip = upnp.externalipaddress()
            except Exception:  # noqa: BLE001 - 部分路由器不实现该查询
                external_ip = ""

            upnp.addportmapping(
                port,
                protocol,
                local_ip,
                port,
                description,
                "",
            )
        except UpnpError:
            raise
        except Exception as exc:
            raise UpnpError(f"UPnP 端口映射失败：{exc}") from exc

        self._upnp = upnp
        self._mappings.append((port, protocol))
        logger.info(
            "UPnP 映射成功：%s:%d -> %s:%d",
            external_ip or "公网地址",
            port,
            local_ip,
            port,
        )
        return UpnpMapping(
            external_ip=external_ip,
            local_ip=local_ip,
            port=port,
            protocol=protocol,
        )

    def close(self) -> None:
        if self._upnp is None:
            return
        for port, protocol in self._mappings:
            try:
                self._upnp.deleteportmapping(port, protocol)
            except Exception as exc:  # noqa: BLE001 - 路由器可能已经重启/断开
                logger.debug("删除 UPnP 映射 %s/%d 失败：%s", protocol, port, exc)
        self._mappings.clear()
        self._upnp = None

    def __enter__(self) -> UpnpMapper:  # noqa: PYI034
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
