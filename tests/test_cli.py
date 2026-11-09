"""Settings screen and command output."""

from __future__ import annotations

import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from scalvs_metatron.cli import main
from scalvs_metatron.settings import ENV_GEO_ENABLED


def run(argv: list[str]) -> tuple[int, str, str]:
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {
            name: os.environ.get(name)
            for name in (
                ENV_GEO_ENABLED,
                "SCALVS_GEO_DATA_DIR",
                "SCALVS_GEO_LOCKFILE",
                "SCALVS_METATRON_ROOT",
                "SCALVS_METATRON_CONFIG",
            )
        }
        for name in self._saved:
            os.environ.pop(name, None)
        self.tmp = TemporaryDirectory()
        self.config = str(Path(self.tmp.name) / "settings.json")

    def tearDown(self) -> None:
        self.tmp.cleanup()
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_settings_default_and_persist(self) -> None:
        code, out, err = run(["settings", "--config", self.config])
        self.assertEqual(code, 0, err)
        self.assertIn("geo-routing: off", out)
        self.assertIn("effective: off", out)
        self.assertIn("source: default", out)
        code, out, err = run(["settings", "--config", self.config, "--geo-routing", "on"])
        self.assertEqual(code, 0, err)
        self.assertIn("geo-routing: on", out)
        self.assertIn("effective: on", out)
        self.assertIn("source: config", out)
        code, out, _err = run(["settings", "--config", self.config])
        self.assertEqual(code, 0)
        self.assertIn("geo-routing: on", out)

    def test_annotate_and_policy_match_when_off(self) -> None:
        code, out, err = run(
            ["annotate", "--config", self.config, "--ip", "192.0.2.1", "--domain", "mail.google.com"]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), {"ip": "192.0.2.1", "domain": "mail.google.com"})
        code, out, err = run(
            ["policy", "--config", self.config, "--ip", "192.0.2.1", "--domain", "mail.google.com"]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), {"route": "default"})

    def test_environment_off_keeps_the_default_output(self) -> None:
        run(["settings", "--config", self.config, "--geo-routing", "on"])
        os.environ[ENV_GEO_ENABLED] = "off"
        code, out, err = run(["policy", "--config", self.config, "--ip", "8.8.8.8"])
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), {"route": "default"})

    def test_on_without_datasets_does_not_pretend_to_be_off(self) -> None:
        empty = Path(self.tmp.name) / "empty-geo"
        empty.mkdir()
        os.environ["SCALVS_GEO_DATA_DIR"] = str(empty)
        os.environ["SCALVS_GEO_LOCKFILE"] = str(Path(self.tmp.name) / "missing.lock.json")
        code, out, err = run(
            ["policy", "--config", self.config, "--geo-routing", "--ip", "192.0.2.1"]
        )
        self.assertEqual(code, 1, out)
        self.assertIn("lockfile", err)
        self.assertEqual(out, "")

    def test_invalid_environment_is_an_error(self) -> None:
        os.environ[ENV_GEO_ENABLED] = "maybe"
        code, _out, err = run(["settings", "--config", self.config])
        self.assertEqual(code, 1)
        self.assertIn(ENV_GEO_ENABLED, err)
