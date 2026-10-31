from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from minecraft_tunnel.config import AppConfig, ConfigStore


class ConfigStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self.path = Path(self._temp_dir.name) / "game_net_config.json"
        self.store = ConfigStore(self.path)

    def test_missing_file_returns_defaults(self) -> None:
        self.assertEqual(self.store.load(), AppConfig())

    def test_roundtrip(self) -> None:
        config = AppConfig(
            last_host="mc.example.com",
            last_port=57575,
            last_remote_port=57576,
            local_server="127.0.0.1:25566",
            local_listen_port=25567,
            enable_upnp=False,
            max_players=4,
        )
        self.store.save(config)
        self.assertEqual(self.store.load(), config)

        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(raw["last_host"], "mc.example.com")
        self.assertFalse(raw["enable_upnp"])

    def test_partial_and_legacy_config(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "last_host": "192.168.1.2",
                    "last_port": 57575,
                    "enable_compression": True,
                    "enable_upnp": False,
                }
            ),
            encoding="utf-8",
        )
        config = self.store.load()
        self.assertEqual(config.last_host, "192.168.1.2")
        self.assertEqual(config.last_port, 57575)
        self.assertEqual(config.last_remote_port, 25565)
        self.assertFalse(config.enable_upnp)
        self.assertEqual(config.local_server, "127.0.0.1:25565")
        self.assertEqual(config.local_listen_port, 25566)

    def test_invalid_json_returns_defaults(self) -> None:
        self.path.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.store.load(), AppConfig())

    def test_non_object_json_returns_defaults(self) -> None:
        self.path.write_text("[]", encoding="utf-8")
        self.assertEqual(self.store.load(), AppConfig())

    def test_invalid_values_fall_back(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "last_port": 99999,
                    "local_server": "not a valid endpoint",
                    "local_listen_port": -5,
                    "enable_upnp": "maybe",
                    "max_players": True,
                }
            ),
            encoding="utf-8",
        )
        config = self.store.load()
        self.assertEqual(config.last_port, 57575)
        self.assertEqual(config.last_remote_port, 25565)
        self.assertEqual(config.local_server, "127.0.0.1:25565")
        self.assertEqual(config.local_listen_port, 25566)
        self.assertTrue(config.enable_upnp)
        self.assertEqual(config.max_players, 8)

    def test_save_creates_parent_and_leaves_no_temp_files(self) -> None:
        nested = Path(self._temp_dir.name) / "a" / "b" / "config.json"
        store = ConfigStore(nested)
        store.save(AppConfig())
        self.assertTrue(nested.exists())
        self.assertEqual(list(nested.parent.glob(".*.tmp")), [])

    def test_utf8_content(self) -> None:
        config = AppConfig(last_host="例子.测试")
        self.store.save(config)
        self.assertEqual(self.store.load().last_host, "例子.测试")

    def test_utf8_bom_is_accepted(self) -> None:
        self.path.write_text('\ufeff{"last_port": 57575}', encoding="utf-8")
        self.assertEqual(self.store.load().last_port, 57575)


if __name__ == "__main__":
    unittest.main()
