"""Opt-in geo hook for cyber policy, annotation, and logging.

The hook returns the original record and does not read datasets when geo
routing is off, so the default path stays unchanged.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from scalvs_metatron.geo_fetch import GeoChecksumError, load_lock, sha256_file
from scalvs_metatron.geo_loader import GeoDataset, GeoDataError
from scalvs_metatron.paths import geo_data_dir, geo_lock_path
from scalvs_metatron.settings import is_geo_enabled

logger = logging.getLogger("scalvs_metatron.geo")

_CACHE: dict[tuple[str, str], GeoDataset] = {}


def clear_geo_cache() -> None:
    _CACHE.clear()


def load_configured_dataset() -> GeoDataset:
    """Load the pinned datasets after their checksums match the lockfile."""
    lock_path = geo_lock_path()
    if not lock_path.is_file():
        raise GeoDataError(f"geo lockfile not found: {lock_path}")
    lock = load_lock(lock_path)
    expected = {entry["save_as"]: entry["sha256"] for entry in lock["datasets"]}
    data_dir = geo_data_dir()
    paths = {}
    digests = []
    for name in ("geoip.dat", "geosite.dat"):
        path = data_dir / name
        if not path.is_file():
            raise GeoDataError(
                f"geo dataset {name} is not in {data_dir}. Run scripts/fetch_geo_data.py."
            )
        digest = sha256_file(path)
        if digest != expected.get(name):
            raise GeoChecksumError(
                f"checksum mismatch for {name}: file {digest} does not match "
                f"lockfile {expected.get(name)}. Refusing to load."
            )
        paths[name] = path
        digests.append(digest)
    key = (digests[0], digests[1])
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    dataset = GeoDataset.from_files(paths["geoip.dat"], paths["geosite.dat"])
    _CACHE.clear()
    _CACHE[key] = dataset
    if dataset.skipped_rules:
        logger.warning(
            "geo dataset skipped %s rules that could not be indexed",
            dataset.skipped_rules,
        )
    return dataset


def _value(record: Mapping | None, explicit: str | None, key: str) -> str | None:
    if explicit is not None:
        return explicit
    if record is None:
        return None
    value = record.get(key)
    if value is None:
        return None
    return str(value)


def annotate(
    record: Mapping,
    *,
    ip: str | None = None,
    domain: str | None = None,
    config_path=None,
    flag: bool | None = None,
    dataset: GeoDataset | None = None,
):
    """Return ``record`` unchanged when geo routing is off.

    When it is on, return a copy with ``geo.countries`` and ``geo.categories``
    and write one log line.
    """
    if not is_geo_enabled(config_path=config_path, flag=flag):
        return record
    active = dataset if dataset is not None else load_configured_dataset()
    ip_value = _value(record, ip, "ip")
    domain_value = _value(record, domain, "domain")
    countries = active.lookup_ip(ip_value) if ip_value else []
    categories = active.lookup_domain(domain_value) if domain_value else []
    annotated = dict(record)
    annotated["geo"] = {"countries": countries, "categories": categories}
    logger.info(
        "geo annotation countries=%s categories=%s",
        ",".join(countries) if countries else "-",
        ",".join(categories) if categories else "-",
    )
    return annotated


def policy_decision(
    record: Mapping | None = None,
    *,
    ip: str | None = None,
    domain: str | None = None,
    config_path=None,
    flag: bool | None = None,
    dataset: GeoDataset | None = None,
) -> dict:
    """Cyber policy decision. Off keeps the default route and adds nothing."""
    if not is_geo_enabled(config_path=config_path, flag=flag):
        return {"route": "default"}
    annotated = annotate(
        {},
        ip=_value(record, ip, "ip"),
        domain=_value(record, domain, "domain"),
        config_path=config_path,
        flag=True,
        dataset=dataset,
    )
    return {"route": "default", "geo": annotated["geo"]}
