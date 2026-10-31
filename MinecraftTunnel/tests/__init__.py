"""测试包。"""

from __future__ import annotations

import logging

# 测试中不输出库内部的 warning（正式入口会配置日志）。
logging.getLogger().addHandler(logging.NullHandler())
