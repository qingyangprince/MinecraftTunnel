# Minecraft 联机助手（重构版 v2.0）

一个用 Python 编写的 Minecraft **Java 版**联机工具：把本机的 Minecraft 服务端通过 TCP 端口转发给局域网或公网的好友。

原来的单文件 `main.py` 已拆成可维护的包，并修复了“看起来能联机、实际收包就崩溃”的核心问题。

---

## 重构说明：原版为什么不能用

原版并不是 Minecraft 转发器，而是一个自定义的 `MCPN` 数据广播器：

| 原版问题 | 后果 |
| --- | --- |
| 在数据前插入 10 字节自定义协议头 | Minecraft 客户端/服务端无法识别，协议被破坏 |
| 收到数据后调用 `self._broadcast(...)` | 该方法根本不存在，第一条数据就会 `AttributeError` |
| 从未连接本机 Minecraft 服务端 | 即使不崩溃，也只是把数据广播给其他客户端 |
| 启动 `_udp_listener` 线程 | 该方法也不存在，UDP 功能是空的 |
| `recv` 不处理半包、`zlib.decompress` 后直接广播 | 大包/压缩包会损坏，连接不稳定 |
| 统计里的 `bytes_sent`/`packets_sent` 从不更新 | 统计信息失真 |
| 玩家上限硬编码、UPnP 在端口绑定前执行 | 配置不生效，端口冲突时提示混乱 |

重构后不再解析或修改 Minecraft 协议，只做**透明的 TCP 双向转发**。这样 Minecraft 的握手、压缩、加密、登录和游戏数据都原样通过，兼容 Java 版服务端和客户端。

---

## 功能

- **创建房间（host）**：监听一个端口，把每位好友的连接转发到本机 Minecraft 服务端（默认 `127.0.0.1:25565`）。
- **加入房间（join）**：在本机监听一个端口，转发到好友的主机；适合把远程房间映射成本地地址。
- **多玩家**：每条连接独立建立上游连接，不共享、不广播。
- **UPnP 自动端口映射**（可选）：安装 `miniupnpc` 后自动尝试在路由器上开放端口。
- **原子配置**：配置写入使用临时文件 + 替换，断电不会留下半个 JSON；兼容旧配置。
- **运行统计**：在线连接数、累计连接数、上下行字节数。
- **交互式菜单**：保留原来的 `python main.py` 用法。
- **UTF-8 输出**：Windows 管道/重定向下中文不再乱码。
- **测试覆盖**：地址解析、配置读写、转发核心、CLI 子进程端到端。

> 仅支持 Minecraft Java 版（TCP）。基岩版使用 UDP，当前工具不处理。

---

## 环境要求

- Python **3.10+**（在 Python 3.13 上验证）
- Minecraft Java 版服务端或“对局域网开放”的世界
- 可选：`miniupnpc`（UPnP 自动映射）

不需要安装任何必装第三方库。

---

## 快速开始

### 1. 房主创建房间

先启动 Minecraft 服务端（或进入世界后“对局域网开放”），确认端口，例如 `25565`。然后：

```bash
python main.py host -p 57575
```

输出示例：

```text
============================================================
  房间已创建，把下面的地址发给好友
============================================================
  局域网地址 : 192.168.1.10:57575
  公网地址   : 需要在路由器把 TCP 57575 转发到 192.168.1.10:57575，再使用公网 IP
  本机测试   : 127.0.0.1:57575
  转发目标   : 127.0.0.1:25565
------------------------------------------------------------
  好友操作：Minecraft -> 多人游戏 -> 直接连接 -> 输入上面的地址
  停止房间：按 Ctrl+C
============================================================
```

好友在 Minecraft 中依次点击 **多人游戏 → 直接连接**，输入 `房主地址:57575` 即可。

按 `Ctrl+C` 停止房间。

### 2. 好友加入房间（可选）

如果好友想使用一个固定的本地地址，可以运行：

```bash
python main.py join -H <房主公网或局域网 IP> -p 57575
```

然后让 Minecraft 连接 `127.0.0.1:25566`（默认本地端口）。启动时会先检测主机端口是否可连接。

> 直接连接房主地址通常就够了；join 模式主要方便本地地址固定、或客户端不方便直接访问远程地址的场景。

### 3. 交互式菜单

```bash
python main.py
```

菜单包含：创建房间、加入好友房间、设置、退出。

### 4. 安装为命令（可选）

```bash
pip install -e .
mc-tunnel host -p 57575
```

也可以使用模块方式：

```bash
python -m minecraft_tunnel host -p 57575
```

---

## 工作原理

host 模式：

```text
好友 Minecraft 客户端
        │  TCP
        ▼
房主公网/局域网 IP:57575
        │
        ▼
mc-tunnel host（本工具）
        │  TCP
        ▼
127.0.0.1:25565（Minecraft 服务端）
```

join 模式：

```text
本机 Minecraft 客户端
        │  TCP 127.0.0.1:25566
        ▼
mc-tunnel join（本工具）
        │  TCP
        ▼
好友主机 IP:57575
        │
        ▼
好友的 Minecraft 服务端
```

工具只复制字节流，不添加协议头、不做压缩/解压、不解析数据包。每条连接都对应一个独立的上游连接，支持多名玩家同时在线。

---

## 公网访问

### 同一局域网

好友直接使用输出里的“局域网地址”即可，通常不需要 UPnP 或端口转发。

### 互联网

房主需要满足以下条件之一：

1. **UPnP 自动映射成功**：安装 `miniupnpc` 并保持路由器开启 UPnP。工具会在创建房间时尝试映射 TCP 端口。
2. **手动端口转发**：在路由器管理界面把公网 `TCP 57575` 转发到房主电脑的 `192.168.x.x:57575`。
3. **已有公网 IP / 端口映射**：直接把公网地址发给好友。

同时请确认：

- Windows 防火墙首次弹窗时允许 Python 访问网络；如果错过了，可在“允许应用通过防火墙”中手动放行。
- 房主没有被运营商 NAT（CGNAT）限制。如果路由器 WAN 口地址是 `10.x`、`100.64.x`、`172.16.x` 等内网地址，UPnP/端口转发通常也无法从公网访问，需要 frp、ZeroTier、Radmin VPN 等额外方案。

> 当前工具不提供中继服务器；它只做端口转发。

---

## 安全提示

这是一个**裸 TCP 转发器**：

- 没有加密、没有认证、没有访问控制。
- 任何知道 `公网 IP:端口` 的人都能连接到你的 Minecraft 服务端。
- 请依赖 Minecraft 自身的安全机制：`online-mode=true`、白名单（whitelist）、正版验证、服务端权限插件等。
- 不要把这个端口转发到非 Minecraft 服务，也不要把管理端口暴露到公网。

原版的自定义协议同样没有加密，本次重构没有降低安全性；相反，移除了不必要的私有协议层，减少攻击面。

---

## 命令行参考

```text
python main.py                         打开交互式菜单
python main.py host [选项]             创建房间
python main.py join -H 地址 [选项]     加入好友房间
python main.py config [选项]           查看/修改配置
python main.py menu                    显式打开菜单
```

### host

| 选项 | 说明 |
| --- | --- |
| `-p, --port` | 对外监听端口；默认读取配置，首次为 `57575`（避免和 Minecraft 服务端的 `25565` 冲突） |
| `-t, --target` | 本机 Minecraft 服务端地址，默认 `127.0.0.1:25565` |
| `--bind` | 监听地址，默认 `0.0.0.0`（允许局域网/公网） |
| `--no-upnp` | 本次不尝试 UPnP |
| `--stats-interval` | 统计日志间隔（秒），`0` 关闭，默认 `30` |

### join

| 选项 | 说明 |
| --- | --- |
| `-H, --host` | 好友主机地址（IP/域名，也可写成 `地址:端口`） |
| `-p, --port` | 好友主机端口；默认读取配置，首次为 `25565` |
| `-l, --listen` | 本机监听端口；默认读取配置，首次为 `25566` |
| `--bind` | 本机监听地址，默认 `127.0.0.1` |
| `--no-check` | 启动前不检测主机连通性 |
| `--stats-interval` | 统计日志间隔（秒），`0` 关闭，默认 `30` |

### config

```bash
python main.py config --show
python main.py config --set enable_upnp false
python main.py config --set local_server 127.0.0.1:25566
python main.py config --set local_listen_port 25567
python main.py config --reset
```

支持的配置项：`last_host`、`last_port`、`last_remote_port`、`local_server`、`local_listen_port`、`enable_upnp`、`max_players`。

---

## 配置文件

默认路径：

```text
<项目根目录>/game_net_config.json
```

源码运行时固定在项目根目录，不随当前工作目录变化；通过 wheel 安装时回退到用户配置目录（Windows 为 `%APPDATA%\MinecraftTunnel\game_net_config.json`）。可以用环境变量覆盖：

```bash
# PowerShell
$env:MC_TUNNEL_CONFIG = "D:\mc\config.json"
python main.py
```

示例：

```json
{
  "last_host": "192.168.1.2",
  "last_port": 57575,
  "last_remote_port": 57575,
  "local_server": "127.0.0.1:25565",
  "local_listen_port": 25566,
  "enable_upnp": true,
  "max_players": 8
}
```

兼容说明：

- `last_port` 记录创建房间时对外监听的端口（首次默认 `57575`）。
- `last_remote_port` 记录加入房间时好友主机的端口（首次默认 `25565`）。
- 旧的 `enable_compression` 会被忽略。TCP 是字节流，压缩由 Minecraft 协议自己处理；在转发层解压会破坏数据。
- `max_players` 仅为兼容旧配置保留，实际人数由 Minecraft 服务端控制。
- 缺失的字段自动补默认值；非法值回退默认值，不会导致程序启动失败。

---

## 项目结构

```text
MinecraftTunnel/
├── main.py                     # 兼容入口：python main.py
├── minecraft_tunnel/
│   ├── __init__.py             # 版本与常量
│   ├── __main__.py             # python -m minecraft_tunnel
│   ├── cli.py                  # 参数解析、交互菜单、输出
│   ├── config.py               # 配置 dataclass、加载/原子保存/迁移
│   ├── forward.py              # TCP 转发核心（监听、会话、双向复制）
│   ├── log.py                  # 日志格式与颜色
│   ├── net.py                  # 地址解析、端口校验、本机 IP
│   ├── stats.py                # 线程安全统计与格式化
│   └── upnp.py                 # 可选 UPnP 端口映射
├── tests/
│   ├── test_cli.py
│   ├── test_cli_integration.py
│   ├── test_config.py
│   ├── test_forward.py
│   ├── test_net.py
│   ├── test_stats.py
│   └── helpers.py
├── packaging/
│   └── version_info.txt        # Windows exe 版本资源
├── pyproject.toml
├── MANIFEST.in
├── game_net_config.json        # 本地配置（可用 MC_TUNNEL_CONFIG 覆盖）
└── README.md
```

---

## 运行测试

```bash
python -m unittest discover -s tests -v
```

当前包含 45 个测试，覆盖：

- `主机:端口` / IPv6 地址解析、端口校验
- 配置默认值、旧配置迁移、坏 JSON、原子写入
- TCP 转发：单连接、多连接、512 KB 大包、端口占用、目标不可达、停止监听、统计
- CLI 子进程端到端：真实启动 `main.py host` 和 `main.py join` 并收发数据

---

## 打包与发布

### 生成 wheel / sdist

```bash
python -m pip install build
python -m build
```

产物在 `dist/`：

- `minecraft_tunnel-2.0.0-py3-none-any.whl`
- `minecraft_tunnel-2.0.0.tar.gz`

安装 wheel：

```bash
pip install dist/minecraft_tunnel-2.0.0-py3-none-any.whl
mc-tunnel --version
```

### 生成 Windows 单文件 exe

```bash
pip install pyinstaller miniupnpc
pyinstaller --noconfirm --clean --onefile --console --name mc-tunnel --hidden-import miniupnpc --version-file packaging/version_info.txt main.py
```

或者直接使用仓库中已生成的 `dist/mc-tunnel.exe`。exe 会把 `game_net_config.json` 放在 exe 同级目录；也可以用 `MC_TUNNEL_CONFIG` 环境变量指定位置。

> exe 未做代码签名，Windows SmartScreen 可能提示“未知发布者”。这是正常的，校验 `SHA256SUMS.txt` 后再运行即可。

---

## 常见问题

**端口被占用**

换一个端口，例如 `python main.py host -p 57576`。Windows 上不使用 `SO_REUSEADDR`，因此冲突会明确报错，而不是悄悄复用端口。

**好友连不上**

按顺序检查：

1. 房主本机能否用 `127.0.0.1:57575` 连接（可用 Minecraft 直接连接测试）。
2. 同一局域网的好友能否用“局域网地址”连接。
3. Windows 防火墙是否允许 Python。
4. 路由器是否做了 TCP 端口转发，或 UPnP 是否成功。
5. 房主是否有公网 IP（不是 CGNAT）。

**UPnP 失败**

安装 `miniupnpc`：

```bash
pip install miniupnpc
# 或者
pip install -r requirements-optional.txt
```

如果仍然失败，手动在路由器上做端口转发即可。部分路由器不支持 UPnP 或关闭了该功能。

**为什么不再有“数据压缩”设置**

Minecraft 协议自身会协商压缩。转发层必须保持字节流原样，任何额外的 `zlib.decompress` 都会让 Minecraft 无法解析。旧配置里的 `enable_compression` 会被忽略。

**能支持基岩版吗**

不能。基岩版使用 UDP，当前实现是 TCP 转发。Java 版联机请使用本工具；基岩版需要专门的 UDP 转发工具。

**会不会影响正版验证/皮肤/聊天**

不会。转发是透明的，Minecraft 服务端的 `online-mode`、白名单、皮肤、聊天和插件都照常工作。前提是服务端本身配置正确。

---

## 已知限制

- 仅 TCP，仅 Minecraft Java 版。
- 不提供中继/打洞服务；公网访问依赖 UPnP、手动端口转发或已有公网 IP。
- 无加密和认证，暴露端口即暴露 Minecraft 服务端。
- 每条连接使用两个转发线程；适合小型好友联机，不适合大规模公网服。
