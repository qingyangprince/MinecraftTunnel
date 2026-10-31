"""支持 ``python -m minecraft_tunnel``。"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
