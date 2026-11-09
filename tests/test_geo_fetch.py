"""Fetch-script tests. They do not contact the network."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from scalvs_metatron.geo_fetch import (
    GeoChecksumError,
    GeoFetchError,
    fetch_datasets,
    load_lock,
    main,
    parse_sha256sum,
    validate_entry,
    validate_redirect,
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "data" / "geo.lock.json"
GEOIP_SHA = "eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2"
GEOSITE_SHA = "dc4192dd1b644a38276ed06136d26e729fa674d25785adb38c87e040e92376b2"
GEOIP_URL = "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat"
DLC_URL = (
    "https://github.com/v2fly/domain-list-community/releases/download/20261108011013/dlc.dat"
)


class MapTransport:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.downloads: list[str] = []
        self.reads: list[str] = []

    def read_text(self, url: str) -> str:
        self.reads.append(url)
        if url not in self.files:
            raise GeoFetchError(f"missing {url}")
        return self.files[url].decode("utf-8")

    def download(self, url: str, dest: Path) -> None:
        self.downloads.append(url)
        if url not in self.files:
            raise GeoFetchError(f"missing {url}")
        dest.write_bytes(self.files[url])


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _entry(source: str, tag: str, asset: str, save_as: str, payload: bytes) -> dict:
    repo = source.split("/", 1)[1]
    url = f"https://github.com/v2fly/{repo}/releases/download/{tag}/{asset}"
    return {
        "name": save_as,
        "source": source,
        "tag": tag,
        "asset": asset,
        "url": url,
        "sha256_url": url + ".sha256sum",
        "sha256": _digest(payload),
        "license": "test",
        "save_as": save_as,
    }


def _lock(entries: list[dict]) -> dict:
    return {"datasets": entries}


class LockfileTest(unittest.TestCase):
    def test_pinned_v2fly_assets(self) -> None:
        lock = load_lock(LOCK)
        by_name = {entry["save_as"]: entry for entry in lock["datasets"]}
        geoip = by_name["geoip.dat"]
        geosite = by_name["geosite.dat"]
        self.assertEqual(geoip["source"], "v2fly/geoip")
        self.assertEqual(geoip["tag"], "202611080027")
        self.assertEqual(geoip["asset"], "geoip.dat")
        self.assertEqual(geoip["url"], GEOIP_URL)
        self.assertEqual(geoip["sha256_url"], GEOIP_URL + ".sha256sum")
        self.assertEqual(geoip["sha256"], GEOIP_SHA)
        self.assertEqual(geoip["license"], "CC-BY-SA-4.0")
        self.assertEqual(geosite["source"], "v2fly/domain-list-community")
        self.assertEqual(geosite["tag"], "20261108011013")
        self.assertEqual(geosite["asset"], "dlc.dat")
        self.assertEqual(geosite["url"], DLC_URL)
        self.assertEqual(geosite["sha256_url"], DLC_URL + ".sha256sum")
        self.assertEqual(geosite["sha256"], GEOSITE_SHA)
        self.assertEqual(geosite["license"], "MIT")
        notices = (ROOT / "THIRD_PARTY_NOTICES").read_text(encoding="utf-8")
        self.assertIn(GEOIP_SHA, notices)
        self.assertIn(GEOSITE_SHA, notices)
        self.assertIn("CC-BY-SA-4.0", notices)
        self.assertIn("MIT License", notices)
        self.assertIn("IP Geolocation data by DB-IP", notices)
        self.assertIn("Loyalsoldier", notices)
        self.assertIn("sing-box", notices)

    def test_binaries_are_gitignored(self) -> None:
        target = ROOT / "data" / "geo" / "geoip.dat"
        created = False
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(b"synthetic")
            created = True
        try:
            result = subprocess.run(
                ["git", "check-ignore", "-q", "data/geo/geoip.dat"],
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(result.returncode, 0)
        finally:
            if created:
                target.unlink()


class ValidationTest(unittest.TestCase):
    def test_parse_sha256sum_formats(self) -> None:
        digest = "ab" * 32
        self.assertEqual(parse_sha256sum(f"{digest}  geoip.dat\n", "geoip.dat"), digest)
        self.assertEqual(parse_sha256sum(f"{digest} *dlc.dat\n", "dlc.dat"), digest)

    def test_conflicting_sum_lines(self) -> None:
        text = f"{'ab' * 32}  geoip.dat\n{'cd' * 32}  geoip.dat\n"
        with self.assertRaises(GeoChecksumError):
            parse_sha256sum(text, "geoip.dat")

    def test_refuses_other_publishers(self) -> None:
        entry = _entry("v2fly/geoip", "202611080027", "geoip.dat", "geoip.dat", b"a")
        entry["url"] = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/x/geoip.dat"
        entry["sha256_url"] = entry["url"] + ".sha256sum"
        with self.assertRaises(GeoFetchError):
            validate_entry(entry)
        entry = _entry("v2fly/geoip", "sing-box-1", "geoip.dat", "geoip.dat", b"a")
        with self.assertRaises(GeoFetchError):
            validate_entry(entry)
        entry = _entry("v2fly/geoip", "202611080027", "geoip.dat", "geoip.dat", b"a")
        entry["source"] = "v2fly/singbox"
        with self.assertRaises(GeoFetchError):
            validate_entry(entry)

    def test_refuses_non_release_host(self) -> None:
        entry = _entry("v2fly/geoip", "202611080027", "geoip.dat", "geoip.dat", b"a")
        entry["url"] = "https://cdn.jsdelivr.net/gh/v2fly/geoip@release/geoip.dat"
        entry["sha256_url"] = entry["url"] + ".sha256sum"
        with self.assertRaises(GeoFetchError):
            validate_entry(entry)

    def test_redirect_hosts(self) -> None:
        validate_redirect(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1?sig=secret"
        )
        with self.assertRaises(GeoFetchError):
            validate_redirect("https://example.com/geoip.dat")
        with self.assertRaises(GeoFetchError):
            validate_redirect("http://github.com/v2fly/geoip/releases/download/t/geoip.dat")


class FetchBehaviorTest(unittest.TestCase):
    def _pair(self, geoip: bytes, geosite: bytes) -> tuple[dict, dict[str, bytes]]:
        geo_entry = _entry("v2fly/geoip", "202611080027", "geoip.dat", "geoip.dat", geoip)
        site_entry = _entry(
            "v2fly/domain-list-community",
            "20261108011013",
            "dlc.dat",
            "geosite.dat",
            geosite,
        )
        files = {
            geo_entry["sha256_url"]: f"{geo_entry['sha256']}  geoip.dat\n".encode(),
            geo_entry["url"]: geoip,
            site_entry["sha256_url"]: f"{site_entry['sha256']}  dlc.dat\n".encode(),
            site_entry["url"]: geosite,
        }
        return _lock([geo_entry, site_entry]), files

    def test_writes_geosite_name_and_skips_a_matching_file(self) -> None:
        lock, files = self._pair(b"geoip-bytes", b"site-bytes")
        with self._temp() as dest:
            lock_path = dest / "geo.lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            data = dest / "out"
            transport = MapTransport(files)
            written = fetch_datasets(lock_path, data, transport)
            self.assertEqual([path.name for path in written], ["geoip.dat", "geosite.dat"])
            self.assertEqual((data / "geosite.dat").read_bytes(), b"site-bytes")
            self.assertEqual(
                transport.downloads,
                [lock["datasets"][0]["url"], lock["datasets"][1]["url"]],
            )
            again = MapTransport(files)
            fetch_datasets(lock_path, data, again)
            self.assertEqual(again.downloads, [])
            self.assertEqual(len(again.reads), 2)

    def test_official_sum_mismatch_stops_before_download(self) -> None:
        lock, files = self._pair(b"geoip-bytes", b"site-bytes")
        files[lock["datasets"][0]["sha256_url"]] = b"0" * 64 + b"  geoip.dat\n"
        with self._temp() as dest:
            lock_path = dest / "geo.lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            transport = MapTransport(files)
            with self.assertRaises(GeoChecksumError) as caught:
                fetch_datasets(lock_path, dest / "out", transport)
            self.assertIn("official .sha256sum", str(caught.exception))
            self.assertEqual(transport.downloads, [])
            self.assertFalse((dest / "out" / "geoip.dat").exists())

    def test_downloaded_bytes_mismatch_removes_partial(self) -> None:
        lock, files = self._pair(b"geoip-bytes", b"site-bytes")
        files[lock["datasets"][0]["url"]] = b"tampered"
        with self._temp() as dest:
            lock_path = dest / "geo.lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            out = dest / "out"
            transport = MapTransport(files)
            with self.assertRaises(GeoChecksumError) as caught:
                fetch_datasets(lock_path, out, transport)
            self.assertIn("partial file removed", str(caught.exception))
            self.assertFalse((out / "geoip.dat").exists())
            self.assertFalse(any(path.name.endswith(".partial") for path in out.iterdir()))
            self.assertFalse((out / "geosite.dat").exists())

    def test_cli_reports_mismatch(self) -> None:
        lock, files = self._pair(b"abc", b"def")
        files[lock["datasets"][1]["sha256_url"]] = b"f" * 64 + b"  dlc.dat\n"
        with self._temp() as dest:
            lock_path = dest / "geo.lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            code = main(
                ["--lock", str(lock_path), "--dest", str(dest / "out")],
                transport=MapTransport(files),
            )
            self.assertEqual(code, 1)
            self.assertTrue((dest / "out" / "geoip.dat").is_file())
            self.assertFalse((dest / "out" / "geosite.dat").exists())

    def _temp(self):
        import tempfile

        class _CM:
            def __enter__(self):
                self._raw = tempfile.TemporaryDirectory()
                return Path(self._raw.__enter__())

            def __exit__(self, exc_type, exc, tb):
                return self._raw.__exit__(exc_type, exc, tb)

        return _CM()
