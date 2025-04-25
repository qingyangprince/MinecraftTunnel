import socket
import threading
import struct
import json
import os
import time
from datetime import datetime

# 配置文件路径
CONFIG_FILE = "game_net_config.json"


class GameProtocol:
    MAGIC = 0x4D43504E  # "MCPN"
    HEADER_FORMAT = "!IHHBB"  # magic(4B) | version(2B) | data_len(2B) | proto_type(1B) | pkt_type(1B)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    HEARTBEAT_INTERVAL = 30  # 心跳间隔(秒)

    @staticmethod
    def create_header(data_len, proto_type, pkt_type):
        return struct.pack(GameProtocol.HEADER_FORMAT,
                           GameProtocol.MAGIC,
                           0x0100,  # version
                           data_len,
                           proto_type,
                           pkt_type)


class GameNetworkManager:
    def __init__(self):
        self.running = True
        self.connections = {}
        self.lock = threading.Lock()
        self.config = self.load_config()

    def load_config(self):
        """加载历史配置"""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        return {"last_host": "", "last_port": 25565}

    def save_config(self):
        """保存当前配置"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f)

    def get_local_ip(self):
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
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

    def start_server(self, port):
        """启动游戏主机"""
        # 输入验证
        valid, result = self.validate_port(port)
        if not valid:
            print(f"❌ 错误：{result}")
            return False

        # 保存配置
        self.config["last_host"] = self.get_local_ip()
        self.config["last_port"] = port
        self.save_config()

        # 显示连接信息
        print("\n" + "=" * 40)
        print(f"✅ 主机创建成功！请将以下信息分享给好友：")
        print(f"IP地址: \033[1;32m{self.get_local_ip()}\033[0m")
        print(f"TCP端口: \033[1;33m{port}\033[0m")
        print(f"UDP端口: \033[1;33m{port + 1}\033[0m")
        print("=" * 40 + "\n")

        # 启动TCP监听
        tcp_thread = threading.Thread(target=self._tcp_listener, args=(port,), daemon=True)
        tcp_thread.start()

        # 启动UDP监听
        udp_thread = threading.Thread(target=self._udp_listener, args=(port + 1,), daemon=True)
        udp_thread.start()

        return True

    def _tcp_listener(self, port):
        """TCP监听核心逻辑"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                s.listen()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 TCP服务已启动 (端口 {port})")

                while self.running:
                    conn, addr = s.accept()
                    with self.lock:
                        self.connections[conn.fileno()] = conn
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🎮 玩家加入: {addr[0]}")
                    threading.Thread(target=self._handle_client, args=(conn,)).start()
            except OSError as e:
                print(f"❌ 端口{port}被占用，请更换端口！")
                self.running = False

    def _udp_listener(self, port):
        """UDP监听核心逻辑"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.bind(('0.0.0.0', port))
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 📡 UDP服务已启动 (端口 {port})")
                while self.running:
                    data, addr = s.recvfrom(4096)
                    header = GameProtocol.create_header(len(data), 1, 0)
                    with self.lock:
                        for conn in list(self.connections.values()):  # 创建副本避免线程冲突
                            try:
                                conn.sendall(header + data)
                            except:
                                self._remove_connection(conn)
            except OSError as e:
                print(f"❌ UDP端口{port}不可用！")

    def _handle_client(self, conn):
        """处理TCP连接"""
        last_heartbeat = time.time()
        try:
            # 心跳检测线程
            threading.Thread(target=self._heartbeat_check, args=(conn,), daemon=True).start()

            while self.running:
                # 设置接收超时
                conn.settimeout(5.0)

                try:
                    header = conn.recv(GameProtocol.HEADER_SIZE)
                    if not header:
                        break

                    # 验证协议头
                    magic, version, data_len, proto_type, pkt_type = struct.unpack(
                        GameProtocol.HEADER_FORMAT, header)
                    if magic != GameProtocol.MAGIC:
                        print("⚠️ 接收到非法数据包")
                        continue

                    # 处理心跳包
                    if pkt_type == 2:
                        last_heartbeat = time.time()
                        continue

                    # 接收游戏数据
                    data = conn.recv(data_len)
                    if proto_type == 0:  # TCP数据
                        self._broadcast(conn, header + data)

                except socket.timeout:
                    # 检查心跳超时
                    if time.time() - last_heartbeat > GameProtocol.HEARTBEAT_INTERVAL * 2:
                        print("💔 心跳丢失，连接已断开")
                        break
                    continue

        except ConnectionResetError:
            print("⚠️ 连接异常中断")
        finally:
            self._remove_connection(conn)

    def _heartbeat_check(self, conn):
        """心跳检测"""
        while self.running:
            time.sleep(GameProtocol.HEARTBEAT_INTERVAL)
            try:
                header = GameProtocol.create_header(0, 0, 2)
                conn.send(header)
            except:
                self._remove_connection(conn)
                break

    def _broadcast(self, sender, data):
        """广播数据（排除发送者）"""
        with self.lock:
            for conn in list(self.connections.values()):
                if conn != sender:
                    try:
                        conn.sendall(data)
                    except:
                        self._remove_connection(conn)

    def _remove_connection(self, conn):
        """安全移除连接"""
        with self.lock:
            if conn.fileno() in self.connections:
                conn.close()
                del self.connections[conn.fileno()]
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚪 玩家离开")


def main_menu():
    print("""
    ==================================
        游戏联机助手 v2.0 🎮
    ==================================
    1. 创建游戏房间 🏠
    2. 加入好友游戏 👥
    3. 退出程序 🚪
    """)

    manager = GameNetworkManager()

    while True:
        choice = input("请输入选项 (1/2/3): ").strip()

        if choice == "1":
            # 使用上次配置
            last_port = manager.config["last_port"]
            port = input(f"请输入主机端口 [默认 {last_port}]: ").strip() or last_port

            if manager.start_server(int(port)):
                input("\n按回车键停止主机...")
                manager.running = False
            break

        elif choice == "2":
            # 自动填充上次连接
            last_host = manager.config.get("last_host", "")
            last_port = manager.config.get("last_port", 25565)

            ip = input(f"输入主机IP [上次: {last_host}]: ").strip() or last_host
            port = input(f"输入主机端口 [默认 {last_port}]: ").strip() or last_port

            if not ip:
                print("❌ 必须输入IP地址！")
                continue

            valid, result = manager.validate_port(port)
            if not valid:
                print(f"❌ {result}")
                continue

            print("\n🔄 尝试连接中...")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5.0)
                    s.connect((ip, int(port)))
                    print("✅ 连接成功！开始游戏吧！")

                    # 保存配置
                    manager.config["last_host"] = ip
                    manager.config["last_port"] = int(port)
                    manager.save_config()

                    input("按回车键退出...")
            except Exception as e:
                print(f"❌ 连接失败: {str(e)}")
                print("可能原因：")
                print("- 主机未启动")
                print("- 防火墙阻挡")
                print("- 网络不可达")
            break

        elif choice == "3":
            print("👋 再见！")
            break

        else:
            print("⚠️ 无效输入，请重新选择")


if __name__ == "__main__":
    main_menu()