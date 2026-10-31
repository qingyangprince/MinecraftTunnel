"""命令行入口与交互式菜单。"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from . import APP_NAME, __version__
from .config import (
    DEFAULT_HOST_PORT,
    DEFAULT_REMOTE_PORT,
    AppConfig,
    ConfigError,
    ConfigStore,
)
from .forward import TcpForwarder, TunnelError
from .log import setup_logging
from .net import (
    DEFAULT_MINECRAFT_PORT,
    Endpoint,
    can_connect,
    get_local_ip,
    is_private_ip,
    parse_endpoint,
    validate_port,
)
from .stats import StatsReporter, TunnelStats, format_bytes, format_duration
from .upnp import UpnpError, UpnpMapper, UpnpMapping

logger = logging.getLogger(__name__)

DEFAULT_BIND = "0.0.0.0"
DEFAULT_JOIN_BIND = "127.0.0.1"
DEFAULT_STATS_INTERVAL = 30


# ----------------------------------------------------------------------
# argparse
# ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mc-tunnel",
        description=(
            "Minecraft 联机助手：通过 TCP 端口转发，让好友连接你的 Minecraft 世界。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python main.py                         打开交互式菜单\n"
            "  python main.py host -p 57575           创建房间（转发到 127.0.0.1:25565）\n"
            "  python main.py join -H 1.2.3.4 -p 57575\n"
            "  python main.py config --show           查看配置\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")

    # 允许把 -v 放在子命令后面，例如 `python main.py host -v`。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="输出调试日志",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="命令")

    host = subparsers.add_parser(
        "host",
        parents=[common],
        help="创建房间：把本机 Minecraft 服务端转发到公网/局域网",
        description="创建房间：监听一个端口，并把每条连接转发到本机 Minecraft 服务端。",
    )
    host.add_argument(
        "-p",
        "--port",
        type=_port_arg,
        help=f"对外监听端口（默认读取配置，首次为 {DEFAULT_HOST_PORT}）",
    )
    host.add_argument(
        "-t",
        "--target",
        metavar="地址:端口",
        help="本机 Minecraft 服务端地址（默认 127.0.0.1:25565）",
    )
    host.add_argument(
        "--bind",
        default=DEFAULT_BIND,
        metavar="地址",
        help=f"监听地址（默认 {DEFAULT_BIND}，允许局域网/公网连接）",
    )
    host.add_argument(
        "--no-upnp", action="store_true", help="不尝试自动配置路由器端口映射"
    )
    _add_stats_option(host)

    join = subparsers.add_parser(
        "join",
        parents=[common],
        help="加入好友房间：在本机建立到主机的转发",
        description="加入好友房间：在本机监听一个端口，把连接转发到好友的主机。",
    )
    join.add_argument(
        "-H",
        "--host",
        required=True,
        metavar="地址",
        help="好友的主机地址（IP 或域名，也可写成 地址:端口）",
    )
    join.add_argument(
        "-p",
        "--port",
        type=_port_arg,
        help=f"好友主机的端口（默认读取配置，首次为 {DEFAULT_REMOTE_PORT}）",
    )
    join.add_argument(
        "-l",
        "--listen",
        type=_port_arg,
        help="本机监听端口（默认读取配置，首次为 25566）",
    )
    join.add_argument(
        "--bind",
        default=DEFAULT_JOIN_BIND,
        metavar="地址",
        help=f"本机监听地址（默认 {DEFAULT_JOIN_BIND}，仅本机可用）",
    )
    join.add_argument(
        "--no-check", action="store_true", help="启动前不检测主机是否可以连接"
    )
    _add_stats_option(join)

    config = subparsers.add_parser(
        "config",
        parents=[common],
        help="查看或修改配置",
        description="查看配置；使用 --set 修改，或使用 --reset 恢复默认。",
    )
    config.add_argument("--show", action="store_true", help="显示当前配置（默认行为）")
    config.add_argument(
        "--set",
        nargs=2,
        action="append",
        metavar=("KEY", "VALUE"),
        help=(
            "修改配置，可重复使用。支持 last_host、last_port、last_remote_port、"
            "local_server、local_listen_port、enable_upnp、max_players"
        ),
    )
    config.add_argument("--reset", action="store_true", help="恢复默认配置")

    subparsers.add_parser(
        "menu",
        parents=[common],
        help="打开交互式菜单（不带参数时的默认行为）",
    )

    return parser


def _add_stats_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--stats-interval",
        type=_interval_arg,
        default=DEFAULT_STATS_INTERVAL,
        metavar="秒",
        help=f"统计日志间隔，0 表示关闭（默认 {DEFAULT_STATS_INTERVAL} 秒）",
    )


def _port_arg(value: str) -> int:
    try:
        return validate_port(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _interval_arg(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("必须是整数秒") from None
    if seconds < 0:
        raise argparse.ArgumentTypeError("不能为负数")
    return seconds


# ----------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)

    store = ConfigStore()
    try:
        config = store.load()
    except ConfigError as exc:
        logger.error("%s", exc)
        logger.warning("本次使用默认配置")
        config = AppConfig()

    try:
        if args.command in (None, "menu"):
            return _interactive(store, config)
        if args.command == "host":
            return _run_host(args, store, config)
        if args.command == "join":
            return _run_join(args, store, config)
        if args.command == "config":
            return _run_config(args, store, config)
        parser.print_help()
        return 2
    except KeyboardInterrupt:
        print()
        logger.info("已取消")
        return 130
    except (TunnelError, ConfigError, UpnpError, ValueError) as exc:
        logger.error("%s", exc)
        return 1


# ----------------------------------------------------------------------
# 子命令实现
# ----------------------------------------------------------------------


def _run_host(args: argparse.Namespace, store: ConfigStore, config: AppConfig) -> int:
    port = args.port if args.port is not None else config.last_port
    target = parse_endpoint(
        args.target or config.local_server, default_port=DEFAULT_MINECRAFT_PORT
    )
    return _serve_host(
        port=port,
        target=target,
        bind=args.bind,
        enable_upnp=config.enable_upnp and not args.no_upnp,
        stats_interval=args.stats_interval,
        store=store,
        config=config,
    )


def _run_join(args: argparse.Namespace, store: ConfigStore, config: AppConfig) -> int:
    remote_port = args.port if args.port is not None else config.last_remote_port
    remote = parse_endpoint(args.host, default_port=remote_port)
    listen_port = args.listen if args.listen is not None else config.local_listen_port
    return _serve_join(
        remote=remote,
        listen_port=listen_port,
        bind=args.bind,
        stats_interval=args.stats_interval,
        check=not args.no_check,
        store=store,
        config=config,
    )


def _run_config(args: argparse.Namespace, store: ConfigStore, config: AppConfig) -> int:
    if args.reset:
        config = AppConfig()
        store.save(config)
        logger.info("配置已恢复默认")

    for key, value in args.set or []:
        config = _apply_setting(config, key, value)
        store.save(config)
        shown = ("true" if value else "false") if isinstance(value, bool) else value
        logger.info("已设置 %s = %s", key, shown)

    _print_config(store, config)
    return 0


def _serve_host(
    *,
    port: int,
    target: Endpoint,
    bind: str,
    enable_upnp: bool,
    stats_interval: int,
    store: ConfigStore,
    config: AppConfig,
) -> int:
    forwarder = TcpForwarder(
        listen_host=bind,
        listen_port=port,
        target_host=target.host,
        target_port=target.port,
        name="host",
    )
    try:
        forwarder.start()
    except TunnelError as exc:
        logger.error("%s", exc)
        return 1

    reporter: StatsReporter | None = None
    mapper: UpnpMapper | None = None
    try:
        reporter = _start_reporter(forwarder.stats, stats_interval)
        mapping: UpnpMapping | None = None
        if enable_upnp:
            logger.info("正在尝试通过 UPnP 自动映射端口...")
            mapper = UpnpMapper()
            try:
                mapping = mapper.map_port(
                    port, protocol="TCP", description="Minecraft Tunnel"
                )
            except UpnpError as exc:
                logger.warning("%s", exc)
                mapper = None
            else:
                if bind in {"127.0.0.1", "localhost", "::1"}:
                    logger.warning(
                        "当前监听地址是 %s，UPnP 映射无法从其他设备访问；"
                        "请改用 --bind 0.0.0.0",
                        bind,
                    )

        config.last_port = port
        config.local_server = str(target)
        _save_config(store, config)

        _print_host_info(
            port=port,
            target=target,
            local_ip=get_local_ip(),
            bind=bind,
            mapping=mapping,
        )

        if can_connect(target, timeout=2.0):
            logger.info("已检测到本机 Minecraft 服务端：%s", target)
        else:
            logger.warning(
                "暂时连不上本机 Minecraft 服务端 %s；请确认游戏服务端已启动、端口正确",
                target,
            )

        try:
            forwarder.wait()
        except KeyboardInterrupt:
            logger.info("收到停止信号，正在关闭房间...")
    finally:
        forwarder.stop()
        if reporter is not None:
            reporter.stop()
        if mapper is not None:
            mapper.close()

    _print_summary(forwarder.stats)
    return 0


def _serve_join(
    *,
    remote: Endpoint,
    listen_port: int,
    bind: str,
    stats_interval: int,
    check: bool,
    store: ConfigStore,
    config: AppConfig,
) -> int:
    if check:
        logger.info("正在检测主机 %s ...", remote)
        if not can_connect(remote, timeout=5.0):
            logger.error(
                "无法连接主机 %s。请确认：\n"
                "  - 好友已经创建房间并保持运行\n"
                "  - 端口号正确\n"
                "  - 双方防火墙/路由器允许该端口",
                remote,
            )
            return 1
        logger.info("主机 %s 可以连接", remote)
    else:
        logger.info("已跳过主机连通性检测")

    forwarder = TcpForwarder(
        listen_host=bind,
        listen_port=listen_port,
        target_host=remote.host,
        target_port=remote.port,
        name="join",
    )
    try:
        forwarder.start()
    except TunnelError as exc:
        logger.error("%s", exc)
        return 1

    reporter: StatsReporter | None = None
    try:
        reporter = _start_reporter(forwarder.stats, stats_interval)

        config.last_host = remote.host
        config.last_remote_port = remote.port
        config.local_listen_port = listen_port
        _save_config(store, config)

        _print_join_info(remote=remote, listen_port=listen_port, bind=bind)

        try:
            forwarder.wait()
        except KeyboardInterrupt:
            logger.info("收到停止信号，正在关闭转发...")
    finally:
        forwarder.stop()
        if reporter is not None:
            reporter.stop()

    _print_summary(forwarder.stats)
    return 0


# ----------------------------------------------------------------------
# 交互式菜单
# ----------------------------------------------------------------------


def _interactive(store: ConfigStore, config: AppConfig) -> int:
    print(f"\n{APP_NAME} v{__version__}")

    while True:
        _print_menu()
        try:
            choice = input("请选择 (1-4): ").strip()
        except EOFError:
            print()
            return 0

        if choice == "1":
            _interactive_host(store, config)
        elif choice == "2":
            _interactive_join(store, config)
        elif choice == "3":
            _interactive_settings(store, config)
        elif choice in {"4", "q", "quit", "exit"}:
            print("再见！")
            return 0
        else:
            print("无效输入，请重新选择。")


def _interactive_host(store: ConfigStore, config: AppConfig) -> None:
    raw_port = _prompt("对外监听端口", str(config.last_port))
    try:
        port = validate_port(raw_port)
    except ValueError as exc:
        logger.error("端口错误：%s", exc)
        return

    raw_target = _prompt("本机 Minecraft 服务端地址", config.local_server)
    try:
        target = parse_endpoint(raw_target, default_port=DEFAULT_MINECRAFT_PORT)
    except ValueError as exc:
        logger.error("地址错误：%s", exc)
        return

    print("提示：请先在 Minecraft 中打开世界或启动服务端。")
    _serve_host(
        port=port,
        target=target,
        bind=DEFAULT_BIND,
        enable_upnp=config.enable_upnp,
        stats_interval=DEFAULT_STATS_INTERVAL,
        store=store,
        config=config,
    )


def _interactive_join(store: ConfigStore, config: AppConfig) -> None:
    prompt = "主机地址（IP 或域名）"
    if config.last_host:
        prompt += f"（上次：{config.last_host}）"
    host = _prompt(prompt, config.last_host)
    if not host:
        logger.error("必须输入主机地址")
        return

    raw_port = _prompt("主机端口", str(config.last_remote_port))
    try:
        remote = parse_endpoint(host, default_port=validate_port(raw_port))
    except ValueError as exc:
        logger.error("地址错误：%s", exc)
        return

    raw_listen = _prompt("本机监听端口", str(config.local_listen_port))
    try:
        listen_port = validate_port(raw_listen)
    except ValueError as exc:
        logger.error("端口错误：%s", exc)
        return

    _serve_join(
        remote=remote,
        listen_port=listen_port,
        bind=DEFAULT_JOIN_BIND,
        stats_interval=DEFAULT_STATS_INTERVAL,
        check=True,
        store=store,
        config=config,
    )


def _interactive_settings(store: ConfigStore, config: AppConfig) -> None:
    while True:
        print("\n设置")
        print(f"  1. 自动 UPnP 端口映射：{'开' if config.enable_upnp else '关'}")
        print(f"  2. 本机 Minecraft 服务端：{config.local_server}")
        print(f"  3. 加入模式本地监听端口：{config.local_listen_port}")
        print("  4. 返回主菜单")
        try:
            choice = input("请选择 (1-4): ").strip()
        except EOFError:
            return

        if choice == "1":
            config.enable_upnp = not config.enable_upnp
            _save_config(store, config)
            print(f"UPnP 已{'开启' if config.enable_upnp else '关闭'}")
        elif choice == "2":
            raw = _prompt("本机 Minecraft 服务端地址", config.local_server)
            try:
                config.local_server = str(
                    parse_endpoint(raw, default_port=DEFAULT_MINECRAFT_PORT)
                )
            except ValueError as exc:
                logger.error("地址错误：%s", exc)
                continue
            _save_config(store, config)
            print(f"已设置为 {config.local_server}")
        elif choice == "3":
            raw = _prompt("加入模式本地监听端口", str(config.local_listen_port))
            try:
                config.local_listen_port = validate_port(raw)
            except ValueError as exc:
                logger.error("端口错误：%s", exc)
                continue
            _save_config(store, config)
            print(f"已设置为 {config.local_listen_port}")
        elif choice in {"4", ""}:
            return
        else:
            print("无效输入，请重新选择。")


# ----------------------------------------------------------------------
# 输出与配置辅助函数
# ----------------------------------------------------------------------


def _print_menu() -> None:
    print(
        """
============================================================
  1. 创建房间（把你的世界分享给好友）
  2. 加入好友房间（在本机建立转发）
  3. 设置
  4. 退出
============================================================"""
    )


def _print_host_info(
    *,
    port: int,
    target: Endpoint,
    local_ip: str,
    bind: str,
    mapping: UpnpMapping | None,
) -> None:
    wildcard = bind in {"0.0.0.0", "::", ""}
    loopback = bind in {"127.0.0.1", "localhost", "::1"}
    if wildcard:
        advertised = local_ip
        has_lan_address = bool(local_ip) and not local_ip.startswith("127.")
    elif loopback:
        advertised = bind
        has_lan_address = False
    else:
        advertised = bind
        has_lan_address = True

    print()
    print("=" * 60)
    print("  房间已创建，把下面的地址发给好友")
    print("=" * 60)
    if loopback:
        print("  监听地址   : 仅本机（好友无法连接；联机请用 --bind 0.0.0.0）")
    elif has_lan_address:
        print(f"  局域网地址 : {Endpoint(advertised, port)}")
    else:
        print("  局域网地址 : 未获取到，请用 ipconfig 查看本机 IPv4 地址")

    if loopback:
        print("  公网地址   : 当前只监听本机，无法从其他设备访问")
    elif mapping is not None:
        external_ip = mapping.external_ip
        if external_ip:
            print(f"  公网地址   : {Endpoint(external_ip, port)}")
            if is_private_ip(external_ip):
                logger.warning(
                    "路由器返回的公网地址 %s 属于内网地址，"
                    "你可能处于运营商 NAT 之后，UPnP 映射未必能从外网访问",
                    external_ip,
                )
        else:
            print(f"  公网地址   : 已做 UPnP 映射，请用路由器显示的公网 IP:{port}")
    else:
        print(
            f"  公网地址   : 需要在路由器把 TCP {port} 转发到 "
            f"{Endpoint(advertised, port)}，再使用公网 IP"
        )

    print(f"  本机测试   : {Endpoint('127.0.0.1', port)}")
    print(f"  转发目标   : {target}")
    print("-" * 60)
    print("  好友操作：Minecraft -> 多人游戏 -> 直接连接 -> 输入上面的地址")
    print("  停止房间：按 Ctrl+C")
    print("  防火墙   ：首次运行时请允许 Python 通过 Windows 防火墙")
    print("=" * 60)
    print()


def _print_join_info(*, remote: Endpoint, listen_port: int, bind: str) -> None:
    connect_host = bind if bind not in {"0.0.0.0", "::"} else get_local_ip()
    print()
    print("=" * 60)
    print("  本机转发已启动")
    print("=" * 60)
    print(f"  在 Minecraft 中添加服务器：{Endpoint(connect_host, listen_port)}")
    print(f"  实际转发到主机        ：{remote}")
    print("  停止转发：按 Ctrl+C")
    print("=" * 60)
    print()


def _print_summary(stats: TunnelStats) -> None:
    snapshot = stats.snapshot()
    print(
        f"本次运行：{format_duration(snapshot.uptime)}，"
        f"连接 {snapshot.total_connections} 个，"
        f"上行 {format_bytes(snapshot.bytes_up)}，"
        f"下行 {format_bytes(snapshot.bytes_down)}"
    )


def _print_config(store: ConfigStore, config: AppConfig) -> None:
    print(f"配置文件：{store.path}")
    print(f"  last_host          = {config.last_host or '(未设置)'}")
    print(f"  last_port          = {config.last_port}（创建房间的监听端口）")
    print(f"  last_remote_port   = {config.last_remote_port}（加入房间的主机端口）")
    print(f"  local_server       = {config.local_server}")
    print(f"  local_listen_port  = {config.local_listen_port}")
    print(f"  enable_upnp        = {'true' if config.enable_upnp else 'false'}")
    print(f"  max_players        = {config.max_players}（兼容项，不生效）")


def _start_reporter(stats: TunnelStats, interval: int) -> StatsReporter | None:
    if interval <= 0:
        return None
    reporter = StatsReporter(stats, interval=float(interval))
    reporter.start()
    return reporter


def _save_config(store: ConfigStore, config: AppConfig) -> None:
    try:
        store.save(config)
    except ConfigError as exc:
        # 配置保存失败不应中断正在运行的房间，只提示即可。
        logger.warning("%s", exc)


def _apply_setting(config: AppConfig, key: str, raw: str) -> AppConfig:
    normalized = key.strip().lower()
    if normalized == "enable_upnp":
        value: object = _parse_bool(raw)
    elif normalized == "local_server":
        value = str(parse_endpoint(raw, default_port=DEFAULT_MINECRAFT_PORT))
    elif normalized in {"local_listen_port", "last_port", "last_remote_port"}:
        value = validate_port(raw)
    elif normalized == "last_host":
        value = raw.strip()
        if not value:
            raise ValueError("last_host 不能为空")
    elif normalized == "max_players":
        try:
            value = int(raw)
        except ValueError:
            raise ValueError("max_players 必须是正整数") from None
        if value <= 0:
            raise ValueError("max_players 必须是正整数")
    else:
        raise ValueError(
            "未知配置项："
            f"{key}；可用项：last_host、last_port、last_remote_port、"
            "local_server、local_listen_port、enable_upnp、max_players"
        )

    data = config.to_dict()
    data[normalized] = value
    return AppConfig.from_mapping(data)


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on", "是", "开"}:
        return True
    if normalized in {"0", "false", "no", "off", "否", "关"}:
        return False
    raise ValueError("布尔值应为 true/false、yes/no、on/off 或 是/否")


def _prompt(message: str, default: str = "") -> str:
    suffix = f" [默认 {default}]" if default else ""
    try:
        value = input(f"{message}{suffix}: ").strip()
    except EOFError:
        raise KeyboardInterrupt from None
    return value or default


def _configure_stdio() -> None:
    """统一使用 UTF-8，避免中文在管道/重定向时变成乱码。"""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(
                encoding="utf-8",
                errors="replace",
                line_buffering=True,
            )
        except (OSError, ValueError):
            pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
