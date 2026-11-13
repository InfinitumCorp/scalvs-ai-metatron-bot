"""Persisted geo-routing toggle."""

from __future__ import annotations

import json
import os
import stat
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scalvs_metatron.settings import (
    ENV_GEO_ENABLED,
    SettingsError,
    describe_geo_routing,
    is_geo_enabled,
    saved_geo_routing,
    set_geo_routing,
)


class SettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._env = os.environ.get(ENV_GEO_ENABLED)
        os.environ.pop(ENV_GEO_ENABLED, None)
        self.tmp = TemporaryDirectory()
        self.config = Path(self.tmp.name) / "settings.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()
        if self._env is None:
            os.environ.pop(ENV_GEO_ENABLED, None)
        else:
            os.environ[ENV_GEO_ENABLED] = self._env

    def test_missing_file_is_off(self) -> None:
        self.assertFalse(saved_geo_routing(self.config))
        self.assertFalse(is_geo_enabled(config_path=self.config))
        state = describe_geo_routing(config_path=self.config)
        self.assertEqual(state["source"], "default")
        self.assertFalse(state["effective"])

    def test_persist_round_trip_and_file_mode(self) -> None:
        set_geo_routing(True, self.config)
        self.assertTrue(saved_geo_routing(self.config))
        mode = stat.S_IMODE(self.config.stat().st_mode)
        self.assertEqual(mode, 0o600)
        stored = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(stored["geo_routing"], True)
        set_geo_routing(False, self.config)
        self.assertFalse(is_geo_enabled(config_path=self.config))
        self.assertEqual(describe_geo_routing(config_path=self.config)["source"], "config")

    def test_preserves_other_keys(self) -> None:
        self.config.write_text('{"theme": "mono"}\n', encoding="utf-8")
        set_geo_routing(True, self.config)
        stored = json.loads(self.config.read_text(encoding="utf-8"))
        self.assertEqual(stored["theme"], "mono")
        self.assertTrue(stored["geo_routing"])

    def test_environment_and_flag_precedence(self) -> None:
        set_geo_routing(True, self.config)
        os.environ[ENV_GEO_ENABLED] = "off"
        self.assertFalse(is_geo_enabled(config_path=self.config))
        self.assertEqual(
            describe_geo_routing(config_path=self.config)["source"],
            "environment",
        )
        self.assertTrue(is_geo_enabled(config_path=self.config, flag=True))
        self.assertEqual(
            describe_geo_routing(config_path=self.config, flag=True)["source"],
            "flag",
        )
        os.environ[ENV_GEO_ENABLED] = "on"
        set_geo_routing(False, self.config)
        self.assertTrue(is_geo_enabled(config_path=self.config))

    def test_invalid_environment_value(self) -> None:
        os.environ[ENV_GEO_ENABLED] = "maybe"
        with self.assertRaises(SettingsError):
            is_geo_enabled(config_path=self.config)

    def test_non_boolean_saved_value(self) -> None:
        self.config.write_text('{"geo_routing": "on"}\n', encoding="utf-8")
        with self.assertRaises(SettingsError):
            saved_geo_routing(self.config)
