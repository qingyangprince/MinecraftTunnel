import socket
import threading
import struct
import json
import os
import time
from datetime import datetime
import sys
import zlib
import logging
from enum import IntEnum

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format='\033[1;34m[%(asctime)s]\033[0m %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# 配置文件路径
CONFIG_FILE = "game_net_config.json"


class PacketType(IntEnum):
    DATA = 0
    COMMAND = 1
    HEARTBEAT = 2
    HANDSHAKE = 3


class GameProtocol:
    MAGIC = 0x4D43504E  # "MCPN"
    VERSION = 0x0200  # 版本2.0
    HEADER_FORMAT = "!IHHBB"  # magic(4B) | version(2B) | data_len(2B) | proto_type(1B) | pkt_type(1B)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    HEARTBEAT_INTERVAL = 30  # 心跳间隔(秒)
    MAX_PLAYERS = 8  # 最大玩家数

    @staticmethod
    def create_header(data_len, proto_type, pkt_type):
        return struct.pack(GameProtocol.HEADER_FORMAT,
                           GameProtocol.MAGIC,
                           GameProtocol.VERSION,
                           data_len,
                           proto_type,
                           pkt_type)


class GameNetworkManager:
    def __init__(self):
        self.running = True
        self.connections = {}
        self.lock = threading.Lock()
        self.config = self.load_config()
        self.player_count = 0
        self.start_time = time.time()
        self.stats = {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0
        }

    def load_config(self):
        """加载历史配置"""
        default_config = {
            "last_host": "",
            "last_port": 25565,
            "enable_compression": True,
            "enable_upnp": True,
            "max_players": 8
        }

        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # 合并配置，确保新版本有所有必要的字段
                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"加载配置文件失败: {e}, 使用默认配置")
                return default_config
        return default_config

    def save_config(self):
        """保存当前配置"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"保存配置失败: {e}")

    def get_local_ip(self):
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logger.warning(f"获取本地IP失败: {e}, 使用回环地址")
            return "127.0.0.1"

    def validate_port(self, port):
        """验证端口有效性"""
        try:
            port = int(port)
            if 1024 <= port <= 65535:
                return True, port
            return False, "端口需在1024-65535之间"
        except ValueError:
            return False, "请输入数字"

    def enable_upnp(self, port):
        """尝试配置UPnP自动端口映射"""
        if not self.config.get("enable_upnp", True):
            return False

        try:
            import miniupnpc
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            upnp.discover()
            upnp.selectigd()
            # 添加TCP端口映射
            upnp.addportmapping(port, 'TCP', upnp.lanaddr, port, 'Minecraft Server', '')
            # 添加UDP端口映射
            upnp.addportmapping(port + 1, 'UDP', upnp.lanaddr, port + 1, 'Minecraft Server', '')
            logger.info("UPnP端口映射已配置")
            return True
        except ImportError:
            logger.warning("未找到miniupnpc库，无法配置UPnP")
        except Exception as e:
            logger.warning(f"UPnP配置失败: {str(e)}")
        return False

    def start_server(self, port):
        """启动游戏主机"""
        # 输入验证
        valid, result = self.validate_port(port)
        if not valid:
            logger.error(f"端口错误: {result}")
            return False

        # 保存配置
        self.config["last_host"] = self.get_local_ip()
        self.config["last_port"] = port
        self.save_config()

        # 尝试UPnP端口映射
        self.enable_upnp(port)

        # 显示连接信息
        logger.info("\n" + "=" * 40)
        logger.info(f"✅ 主机创建成功！请将以下信息分享给好友：")
        logger.info(f"IP地址: \033[1;32m{self.get_local_ip()}\033[0m")
        logger.info(f"TCP端口: \033[1;33m{port}\033[0m")
        logger.info(f"UDP端口: \033[1;33m{port + 1}\033[0m")
        logger.info("=" * 40 + "\n")

        # 启动TCP监听
        tcp_thread = threading.Thread(target=self._tcp_listener, args=(port,), daemon=True)
        tcp_thread.start()

        # 启动UDP监听
        udp_thread = threading.Thread(target=self._udp_listener, args=(port + 1,), daemon=True)
        udp_thread.start()

        # 启动统计信息线程
        stats_thread = threading.Thread(target=self._show_stats, daemon=True)
        stats_thread.start()

        return True

    def _tcp_listener(self, port):
        """TCP监听核心逻辑"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen(GameProtocol.MAX_PLAYERS)
                logger.info(f"🚀 TCP服务已启动 (端口 {port})")

                while self.running:
                    try:
                        conn, addr = s.accept()
                        if self.player_count >= GameProtocol.MAX_PLAYERS:
                            conn.close()
                            logger.warning(f"已达到最大玩家数({GameProtocol.MAX_PLAYERS})，拒绝连接")
                            continue

                        with self.lock:
                            self.connections[conn.fileno()] = conn
                            self.player_count += 1
                        logger.info(f"🎮 玩家加入: {addr[0]} (当前玩家: {self.player_count}/{GameProtocol.MAX_PLAYERS})")
                        threading.Thread(target=self._handle_client, args=(conn,)).start()
                    except Exception as e:
                        logger.error(f"接受连接时出错: {e}")
            except OSError as e:
                logger.error(f"端口{port}被占用，请更换端口！")
                self.running = False

    def _handle_client(self, conn):
        """处理TCP连接"""
        last_heartbeat = time.time()
        client_addr = conn.getpeername()

        try:
            # 发送握手包
            handshake = json.dumps({
                "version": GameProtocol.VERSION,
                "max_players": GameProtocol.MAX_PLAYERS,
                "player_count": self.player_count
            }).encode()

            header = GameProtocol.create_header(len(handshake), 0, PacketType.HANDSHAKE)
            conn.sendall(header + handshake)

            # 心跳检测线程
            threading.Thread(target=self._heartbeat_check, args=(conn,), daemon=True).start()

            while self.running:
                try:
                    # 设置接收超时
                    conn.settimeout(5.0)
                    header = conn.recv(GameProtocol.HEADER_SIZE)

                    if not header:
                        break

                    # 更新统计
                    with self.lock:
                        self.stats['bytes_received'] += len(header)
                        self.stats['packets_received'] += 1

                    # 验证协议头
                    magic, version, data_len, proto_type, pkt_type = struct.unpack(
                        GameProtocol.HEADER_FORMAT, header)

                    if magic != GameProtocol.MAGIC:
                        logger.warning(f"来自 {client_addr} 的非法数据包")
                        continue

                    # 处理心跳包
                    if pkt_type == PacketType.HEARTBEAT:
                        last_heartbeat = time.time()
                        continue

                    # 接收游戏数据
                    data = conn.recv(data_len)
                    with self.lock:
                        self.stats['bytes_received'] += len(data)

                    # 处理压缩数据
                    if self.config.get("enable_compression", True):
                        try:
                            data = zlib.decompress(data)
                        except:
                            pass

                    if proto_type == 0:  # TCP数据
                        self._broadcast(conn, header + data)

                except socket.timeout:
                    # 检查心跳超时
                    if time.time() - last_heartbeat > GameProtocol.HEARTBEAT_INTERVAL * 2:
                        logger.warning(f"💔 心跳丢失，连接已断开: {client_addr}")
                        break
                    continue
                except Exception as e:
                    logger.error(f"处理客户端数据时出错: {e}")
                    break

        except ConnectionResetError:
            logger.warning(f"连接异常中断: {client_addr}")
        finally:
            self._remove_connection(conn)

    def _show_stats(self):
        """显示统计信息"""
        while self.running:
            time.sleep(10)
            with self.lock:
                uptime = int(time.time() - self.start_time)
                hours, remainder = divmod(uptime, 3600)
                minutes, seconds = divmod(remainder, 60)

                logger.info(f"\n📊 服务器统计 (运行时间: {hours:02d}:{minutes:02d}:{seconds:02d})")
                logger.info(f"玩家: {self.player_count}/{GameProtocol.MAX_PLAYERS}")
                logger.info(f"发送: {self.stats['bytes_sent'] / 1024:.1f}KB ({self.stats['packets_sent']}包)")
                logger.info(f"接收: {self.stats['bytes_received'] / 1024:.1f}KB ({self.stats['packets_received']}包)")


def main_menu():
    print("""
    ==================================
        游戏联机助手 v2.0 🎮
    ==================================
    1. 创建游戏房间 🏠
    2. 加入好友游戏 👥
    3. 服务器设置 ⚙️
    4. 退出程序 🚪
    """)

    manager = GameNetworkManager()

    while True:
        choice = input("请输入选项 (1-4): ").strip()

        if choice == "1":
            last_port = manager.config["last_port"]
            port = input(f"请输入主机端口 [默认 {last_port}]: ").strip() or last_port

            if manager.start_server(int(port)):
                input("\n按回车键停止主机...")
                manager.running = False
            break

        elif choice == "2":
            last_host = manager.config.get("last_host", "")
            last_port = manager.config.get("last_port", 25565)

            ip = input(f"输入主机IP [上次: {last_host}]: ").strip() or last_host
            port = input(f"输入主机端口 [默认 {last_port}]: ").strip() or last_port

            if not ip:
                logger.error("必须输入IP地址！")
                continue

            valid, result = manager.validate_port(port)
            if not valid:
                logger.error(result)
                continue

            logger.info("\n🔄 尝试连接中...")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5.0)
                    s.connect((ip, int(port)))

                    # 接收握手信息
                    header = s.recv(GameProtocol.HEADER_SIZE)
                    magic, version, data_len, proto_type, pkt_type = struct.unpack(
                        GameProtocol.HEADER_FORMAT, header)

                    if magic != GameProtocol.MAGIC:
                        logger.error("服务器返回无效响应")
                        continue

                    data = s.recv(data_len)
                    handshake = json.loads(data.decode())
                    logger.info(f"✅ 连接成功！服务器信息:")
                    logger.info(f"版本: {handshake.get('version', '未知')}")
                    logger.info(f"玩家: {handshake.get('player_count', 0)}/{handshake.get('max_players', 8)}")

                    # 保存配置
                    manager.config["last_host"] = ip
                    manager.config["last_port"] = int(port)
                    manager.save_config()

                    input("按回车键退出...")
            except Exception as e:
                logger.error(f"连接失败: {str(e)}")
                logger.error("可能原因：")
                logger.error("- 主机未启动")
                logger.error("- 防火墙阻挡")
                logger.error("- 网络不可达")
            break

        elif choice == "3":
            print("\n⚙️ 服务器设置")
            print(f"1. 启用数据压缩: {'是' if manager.config.get('enable_compression', True) else '否'}")
            print(f"2. 启用UPnP自动映射: {'是' if manager.config.get('enable_upnp', True) else '否'}")
            print(f"3. 返回主菜单")

            setting_choice = input("选择设置项 (1-3): ").strip()
            if setting_choice == "1":
                manager.config["enable_compression"] = not manager.config.get("enable_compression", True)
                manager.save_config()
                print(f"数据压缩已{'启用' if manager.config['enable_compression'] else '禁用'}")
            elif setting_choice == "2":
                manager.config["enable_upnp"] = not manager.config.get("enable_upnp", True)
                manager.save_config()
                print(f"UPnP自动映射已{'启用' if manager.config['enable_upnp'] else '禁用'}")

        elif choice == "4":
            print("👋 再见！")
            break

        else:
            print("⚠️ 无效输入，请重新选择")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n👋 程序已中断")
        sys.exit(0)