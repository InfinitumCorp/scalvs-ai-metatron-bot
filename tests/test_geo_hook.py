"""The geo hook stays invisible until the toggle is on."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scalvs_metatron.geo_fetch import GeoChecksumError
from scalvs_metatron.geo_hook import annotate, clear_geo_cache, policy_decision
from scalvs_metatron.geo_loader import GeoDataError, GeoDataset
from scalvs_metatron.settings import ENV_GEO_ENABLED
from tests.dat_encode import sample_geoip, sample_geosite


class HookTest(unittest.TestCase):
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
        self.config = Path(self.tmp.name) / "settings.json"
        self.dataset = GeoDataset.from_bytes(sample_geoip(), sample_geosite())
        clear_geo_cache()

    def tearDown(self) -> None:
        self.tmp.cleanup()
        clear_geo_cache()
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_off_returns_the_same_record_and_default_policy(self) -> None:
        record = {"ip": "192.0.2.1", "domain": "mail.google.com", "route": "default"}
        self.assertIs(
            annotate(record, config_path=self.config, dataset=self.dataset),
            record,
        )
        self.assertEqual(
            policy_decision(record, config_path=self.config, dataset=self.dataset),
            {"route": "default"},
        )

    def test_off_does_not_log(self) -> None:
        records = self._capture()
        annotate(
            {"ip": "192.0.2.1"},
            config_path=self.config,
            dataset=self.dataset,
        )
        self.assertEqual(records, [])

    def test_on_annotates_and_logs_without_changing_the_default_route(self) -> None:
        record = {"ip": "192.0.2.20", "domain": "Mail.Google.com"}
        records = self._capture()
        annotated = annotate(
            record,
            config_path=self.config,
            flag=True,
            dataset=self.dataset,
        )
        self.assertEqual(
            annotated["geo"],
            {"countries": ["US", "ZZ"], "categories": ["google"]},
        )
        self.assertEqual(record.get("geo"), None)
        decision = policy_decision(
            record,
            config_path=self.config,
            flag=True,
            dataset=self.dataset,
        )
        self.assertEqual(decision["route"], "default")
        self.assertEqual(decision["geo"]["categories"], ["google"])
        self.assertTrue(any("countries=US,ZZ" in item for item in records))
        self.assertTrue(any("categories=google" in item for item in records))

    def test_process_flag_off_beats_a_saved_on_toggle(self) -> None:
        self.config.write_text('{"geo_routing": true}\n', encoding="utf-8")
        record = {"ip": "10.1.2.3"}
        self.assertIs(
            annotate(record, config_path=self.config, flag=False, dataset=self.dataset),
            record,
        )

    def test_configured_files_must_match_the_lock_before_use(self) -> None:
        data = Path(self.tmp.name) / "geo"
        data.mkdir()
        geoip = sample_geoip()
        geosite = sample_geosite()
        (data / "geoip.dat").write_bytes(geoip)
        (data / "geosite.dat").write_bytes(geosite)
        lock = {
            "datasets": [
                _locked("v2fly/geoip", "202611080027", "geoip.dat", "geoip.dat", geoip),
                _locked(
                    "v2fly/domain-list-community",
                    "20261108011013",
                    "dlc.dat",
                    "geosite.dat",
                    geosite,
                ),
            ]
        }
        lock_path = Path(self.tmp.name) / "geo.lock.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        os.environ["SCALVS_GEO_DATA_DIR"] = str(data)
        os.environ["SCALVS_GEO_LOCKFILE"] = str(lock_path)
        annotated = annotate(
            {"ip": "10.1.2.3", "domain": "exact.example"},
            config_path=self.config,
            flag=True,
        )
        self.assertEqual(annotated["geo"]["countries"], ["PRIVATE", "ZZ"])
        self.assertEqual(annotated["geo"]["categories"], ["exact"])
        (data / "geoip.dat").write_bytes(geoip + b"\x00")
        clear_geo_cache()
        with self.assertRaises(GeoChecksumError):
            annotate({"ip": "10.1.2.3"}, config_path=self.config, flag=True)

    def test_missing_dataset_is_an_error_when_on(self) -> None:
        os.environ["SCALVS_GEO_DATA_DIR"] = str(Path(self.tmp.name) / "missing")
        os.environ["SCALVS_GEO_LOCKFILE"] = str(Path(self.tmp.name) / "geo.lock.json")
        with self.assertRaises(GeoDataError):
            annotate({"ip": "192.0.2.1"}, config_path=self.config, flag=True)

    def _capture(self) -> list[str]:
        records: list[str] = []
        handler = logging.Handler()
        handler.emit = lambda item: records.append(item.getMessage())  # type: ignore[method-assign]
        logger = logging.getLogger("scalvs_metatron.geo")
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        self.addCleanup(logger.removeHandler, handler)
        return records


def _locked(source: str, tag: str, asset: str, save_as: str, payload: bytes) -> dict:
    repo = source.split("/", 1)[1]
    url = f"https://github.com/v2fly/{repo}/releases/download/{tag}/{asset}"
    return {
        "name": save_as,
        "source": source,
        "tag": tag,
        "asset": asset,
        "url": url,
        "sha256_url": url + ".sha256sum",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "license": "test",
        "save_as": save_as,
    }
