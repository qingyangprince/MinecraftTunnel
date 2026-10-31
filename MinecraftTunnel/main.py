"""Minecraft 联机助手入口。

保留这个文件名是为了兼容原来的启动方式：

    python main.py

也可以安装后使用 ``mc-tunnel`` 命令，或用 ``python -m minecraft_tunnel``。
"""

from __future__ import annotations

from minecraft_tunnel.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
