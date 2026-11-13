"""Download pinned v2fly geo datasets and refuse a checksum mismatch.

The binaries are written under the gitignored data directory. This module
never accepts Loyalsoldier or sing-box URLs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

from scalvs_metatron.paths import geo_data_dir, geo_lock_path

_RELEASE_URL = re.compile(
    r"^https://github\.com/v2fly/(?P<repo>geoip|domain-list-community)"
    r"/releases/download/(?P<tag>[A-Za-z0-9._-]+)/(?P<asset>[A-Za-z0-9._-]+)$"
)
_ALLOWED = {
    ("v2fly/geoip", "geoip.dat", "geoip.dat"),
    ("v2fly/domain-list-community", "dlc.dat", "geosite.dat"),
}
_FORBIDDEN = ("loyalsoldier", "sing-box", "singbox")
_REDIRECT_HOSTS = {
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github-releases.githubusercontent.com",
}
_MAX_DATASET_BYTES = 64 * 1024 * 1024
_MAX_SUM_BYTES = 4096
_USER_AGENT = "scalvs-metatron-geo-fetch"


class GeoFetchError(RuntimeError):
    """The datasets could not be fetched."""


class GeoChecksumError(GeoFetchError):
    """An official sum or a downloaded file did not match the lockfile."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_url(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _forbidden_name(value: str) -> str | None:
    lowered = value.lower()
    for name in _FORBIDDEN:
        if name in lowered:
            return name
    return None


def _split_https(url: str):
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise GeoFetchError(f"refusing non-https URL {_safe_url(url)}")
    if parts.username or parts.password:
        raise GeoFetchError("refusing a URL that contains credentials")
    return parts


def validate_entry(entry: dict) -> None:
    """Reject anything other than the two pinned v2fly release assets."""
    required = (
        "name",
        "source",
        "tag",
        "asset",
        "url",
        "sha256_url",
        "sha256",
        "license",
        "save_as",
    )
    missing = [key for key in required if key not in entry]
    if missing:
        raise GeoFetchError(f"lockfile entry is missing {', '.join(missing)}")
    for key in ("name", "source", "tag", "asset", "url", "sha256_url", "save_as"):
        found = _forbidden_name(str(entry[key]))
        if found:
            raise GeoFetchError(f"refusing dataset that names {found}")
    pair = (entry["source"], entry["asset"], entry["save_as"])
    if pair not in _ALLOWED:
        raise GeoFetchError(
            "refusing dataset "
            f"{entry.get('source')} asset {entry.get('asset')} "
            f"saved as {entry.get('save_as')}"
        )
    digest = str(entry["sha256"]).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise GeoFetchError("lockfile sha256 must be 64 hex characters")
    entry["sha256"] = digest
    match = _RELEASE_URL.fullmatch(str(entry["url"]))
    if not match:
        raise GeoFetchError(f"refusing URL {_safe_url(str(entry['url']))}")
    repo = entry["source"].split("/", 1)[1]
    if match.group("repo") != repo or match.group("tag") != entry["tag"]:
        raise GeoFetchError("release URL does not match the lockfile source and tag")
    if match.group("asset") != entry["asset"]:
        raise GeoFetchError("release URL asset does not match the lockfile")
    if entry["sha256_url"] != entry["url"] + ".sha256sum":
        raise GeoFetchError("sha256 URL must be the official asset name plus .sha256sum")
    _split_https(entry["url"])
    _split_https(entry["sha256_url"])


def load_lock(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GeoFetchError(f"geo lockfile not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GeoFetchError(f"geo lockfile is not valid JSON: {path}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("datasets"), list):
        raise GeoFetchError("geo lockfile must contain a datasets list")
    if not data["datasets"]:
        raise GeoFetchError("geo lockfile does not list any datasets")
    for entry in data["datasets"]:
        if not isinstance(entry, dict):
            raise GeoFetchError("geo lockfile dataset entry must be an object")
        validate_entry(entry)
    saves = [entry["save_as"] for entry in data["datasets"]]
    if saves != ["geoip.dat", "geosite.dat"]:
        raise GeoFetchError("lockfile must list geoip.dat and then geosite.dat")
    return data


def parse_sha256sum(text: str, asset_name: str) -> str:
    """Return the digest for ``asset_name`` from a coreutils .sha256sum file."""
    found: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            raise GeoChecksumError(f"unrecognized sha256sum line for {asset_name}")
        digest, name = parts[0], parts[-1].lstrip("*")
        if name != asset_name:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            raise GeoChecksumError(f"official sha256sum for {asset_name} is not 64 hex characters")
        lowered = digest.lower()
        if found is not None and found != lowered:
            raise GeoChecksumError(f"official sha256sum lists conflicting hashes for {asset_name}")
        found = lowered
    if found is None:
        raise GeoChecksumError(f"official sha256sum has no entry for {asset_name}")
    return found


def validate_redirect(url: str) -> None:
    parts = _split_https(url)
    host = parts.hostname.lower().rstrip(".")
    if host in _REDIRECT_HOSTS or host == "github.com":
        return
    raise GeoFetchError(f"refusing redirect to {_safe_url(url)}")


class _GuardRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_redirect(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrlTransport:
    """HTTPS transport that only follows GitHub release asset hosts."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_GuardRedirect)

    def read_text(self, url: str) -> str:
        data = self._read(url, _MAX_SUM_BYTES)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GeoFetchError(f"sha256sum asset is not UTF-8: {_safe_url(url)}") from exc

    def download(self, url: str, dest: Path) -> None:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            response = self._opener.open(request, timeout=120)
        except GeoFetchError:
            raise
        except Exception as exc:
            raise GeoFetchError(f"download failed for {_safe_url(url)}") from exc
        with response:
            validate_redirect(response.geturl())
            written = 0
            with dest.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > _MAX_DATASET_BYTES:
                        raise GeoFetchError(
                            f"download exceeded {_MAX_DATASET_BYTES} bytes for {_safe_url(url)}"
                        )
                    handle.write(chunk)

    def _read(self, url: str, limit: int) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            response = self._opener.open(request, timeout=60)
        except GeoFetchError:
            raise
        except Exception as exc:
            raise GeoFetchError(f"download failed for {_safe_url(url)}") from exc
        with response:
            validate_redirect(response.geturl())
            data = response.read(limit + 1)
        if len(data) > limit:
            raise GeoFetchError(f"response exceeded {limit} bytes for {_safe_url(url)}")
        return data


def fetch_datasets(
    lock_path: Path,
    dest_dir: Path,
    transport: UrlTransport | None = None,
) -> list[Path]:
    """Download datasets. Raise GeoChecksumError and stop on a mismatch."""
    client = transport or UrlTransport()
    lock = load_lock(lock_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for entry in lock["datasets"]:
        official_text = client.read_text(entry["sha256_url"])
        official = parse_sha256sum(official_text, entry["asset"])
        expected = entry["sha256"]
        save_as = entry["save_as"]
        if official != expected:
            raise GeoChecksumError(
                f"checksum mismatch for {save_as}: official .sha256sum {official} "
                f"does not match lockfile {expected}. stopped before writing."
            )
        target = dest_dir / save_as
        if target.is_file() and sha256_file(target) == expected:
            print(f"verified existing {save_as} sha256 {expected} ({entry['asset']} {entry['tag']})")
            written.append(target)
            continue
        partial = dest_dir / f".{save_as}.partial"
        try:
            client.download(entry["url"], partial)
            actual = sha256_file(partial)
            if actual != expected:
                raise GeoChecksumError(
                    f"checksum mismatch for {save_as}: downloaded sha256 {actual} "
                    f"does not match expected {expected}. partial file removed."
                )
            partial.replace(target)
        except Exception:
            partial.unlink(missing_ok=True)
            raise
        print(f"verified {save_as} sha256 {expected} ({entry['asset']} {entry['tag']})")
        written.append(target)
    return written


def main(
    argv: list[str] | None = None,
    transport: UrlTransport | None = None,
    default_lock: Path | None = None,
    default_dest: Path | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        prog="fetch_geo_data",
        description=(
            "Download pinned v2fly geoip.dat and geosite.dat into the gitignored "
            "data directory. Official .sha256sum assets are checked first."
        ),
    )
    parser.add_argument("--lock", type=Path, default=default_lock or geo_lock_path())
    parser.add_argument("--dest", type=Path, default=default_dest or geo_data_dir())
    args = parser.parse_args(argv)
    try:
        fetch_datasets(args.lock, args.dest, transport=transport)
    except GeoFetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
