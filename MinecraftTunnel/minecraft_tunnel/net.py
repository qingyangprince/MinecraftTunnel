"""网络地址与端口相关的小工具。"""

from __future__ import annotations

import ipaddress
import socket
from typing import NamedTuple

DEFAULT_MINECRAFT_PORT = 25565


class Endpoint(NamedTuple):
    """一个 ``主机:端口`` 二元组。"""

    host: str
    port: int

    def __str__(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def validate_port(value: object, *, allow_zero: bool = False) -> int:
    """把用户输入转换成合法端口，非法时抛出 ``ValueError``。"""

    if isinstance(value, bool):
        raise ValueError("端口必须是数字")  # noqa: TRY004
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("端口必须是数字") from None

    lower = 0 if allow_zero else 1
    if not lower <= port <= 65535:
        raise ValueError(f"端口必须在 {lower}-65535 之间")
    return port


def parse_endpoint(value: str, default_port: int | None = None) -> Endpoint:
    """解析 ``主机:端口``、``[IPv6]:端口`` 或只给主机（配合默认端口）。

    只接受带方括号的 IPv6 地址，避免 ``::1`` 这类输入产生歧义。
    """

    text = str(value).strip()
    if not text:
        raise ValueError("地址不能为空")

    host = ""
    port_text = ""
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise ValueError("IPv6 地址缺少 ']'，格式应为 [地址]:端口")
        host = text[1:end]
        rest = text[end + 1 :]
        if rest.startswith(":"):
            port_text = rest[1:]
        elif rest:
            raise ValueError("地址格式应为 [IPv6]:端口")
    else:
        if text.count(":") > 1:
            raise ValueError("IPv6 地址请使用 [地址]:端口 格式")
        if ":" in text:
            host, port_text = text.rsplit(":", 1)
        else:
            host = text

    host = host.strip()
    if not host:
        raise ValueError("主机名不能为空")
    if any(char.isspace() for char in host):
        raise ValueError("主机名不能包含空格")

    if port_text:
        port = validate_port(port_text)
    elif default_port is not None:
        port = validate_port(default_port)
    else:
        raise ValueError("地址缺少端口，格式应为 主机:端口")

    return Endpoint(host, port)


def get_local_ip() -> str:
    """尽力获取本机在局域网中的 IPv4 地址。

    UDP ``connect`` 不会真正发包，只用于让系统选择出口网卡；
    完全离线或只有回环地址时返回 ``127.0.0.1``。
    """

    for target in ("8.8.8.8", "1.1.1.1", "223.5.5.5"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.connect((target, 80))
                ip = sock.getsockname()[0]
        except OSError:
            continue
        if ip and ip != "0.0.0.0" and not ip.startswith("127."):
            return ip

    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"
    return ip if ip and ip != "0.0.0.0" and not ip.startswith("127.") else "127.0.0.1"


def can_connect(endpoint: Endpoint, timeout: float = 3.0) -> bool:
    """快速探测目标端口是否可建立 TCP 连接。"""

    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout):
            return True
    except OSError:
        return False


def is_private_ip(value: str) -> bool:
    """判断字符串是否为内网/保留 IP 地址；域名一律返回 ``False``。"""

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    )
