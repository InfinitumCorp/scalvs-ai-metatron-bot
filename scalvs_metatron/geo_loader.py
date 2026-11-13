"""Loader for v2ray GeoIPList and GeoSiteList payloads.

The published v2fly ``.dat`` files are a single protobuf message:

* ``geoip.dat`` is a GeoIPList (country code, CIDR, optional inverse_match).
* ``geosite.dat`` is a GeoSiteList (category code plus domain rules).

Lookups use the standard library only. Geo routing calls this module only
after the operator turns the feature on.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

_MAX_REGEX_LENGTH = 256
_V4_MAPPED_PREFIX = b"\x00" * 10 + b"\xff\xff"


class GeoDataError(ValueError):
    """A geo dataset could not be parsed or queried."""


def _read_varint(buf: memoryview, index: int) -> tuple[int, int]:
    result = 0
    shift = 0
    size = len(buf)
    while True:
        if index >= size:
            raise GeoDataError("truncated protobuf varint")
        byte = buf[index]
        index += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, index
        shift += 7
        if shift > 63:
            raise GeoDataError("protobuf varint is too long")


def _skip(buf: memoryview, index: int, wire_type: int) -> int:
    if wire_type == 0:
        _, index = _read_varint(buf, index)
        return index
    if wire_type == 1:
        index += 8
    elif wire_type == 5:
        index += 4
    elif wire_type == 2:
        length, index = _read_varint(buf, index)
        index += length
    else:
        raise GeoDataError(f"unsupported protobuf wire type {wire_type}")
    if index > len(buf):
        raise GeoDataError("truncated protobuf field")
    return index


def _take_bytes(buf: memoryview, index: int) -> tuple[bytes, int]:
    length, index = _read_varint(buf, index)
    end = index + length
    if length < 0 or end > len(buf):
        raise GeoDataError("truncated protobuf length")
    return bytes(buf[index:end]), end


def _decode_text(raw: bytes, what: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GeoDataError(f"{what} is not valid UTF-8") from exc


def _parse_cidr(payload: bytes) -> tuple[bytes, int]:
    buf = memoryview(payload)
    index = 0
    ip: bytes | None = None
    prefix = 0
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise GeoDataError("invalid protobuf field number")
        if field_number == 1 and wire_type == 2:
            ip, index = _take_bytes(buf, index)
            continue
        if field_number == 2 and wire_type == 0:
            prefix, index = _read_varint(buf, index)
            continue
        index = _skip(buf, index, wire_type)
    if not ip:
        raise GeoDataError("CIDR is missing an address")
    return ip, prefix


def _parse_geoip(payload: bytes) -> tuple[str, bool, list[tuple[bytes, int]]]:
    buf = memoryview(payload)
    index = 0
    code = ""
    inverse = False
    cidrs: list[tuple[bytes, int]] = []
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise GeoDataError("invalid protobuf field number")
        if field_number == 1 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            code = _decode_text(raw, "country code")
            continue
        if field_number == 2 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            cidrs.append(_parse_cidr(raw))
            continue
        if field_number == 3 and wire_type == 0:
            value, index = _read_varint(buf, index)
            inverse = bool(value)
            continue
        index = _skip(buf, index, wire_type)
    return code, inverse, cidrs


def _parse_domain(payload: bytes) -> tuple[int, str]:
    buf = memoryview(payload)
    index = 0
    domain_type = 0
    value = ""
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise GeoDataError("invalid protobuf field number")
        if field_number == 1 and wire_type == 0:
            domain_type, index = _read_varint(buf, index)
            continue
        if field_number == 2 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            value = _decode_text(raw, "domain value")
            continue
        index = _skip(buf, index, wire_type)
    return domain_type, value


def _parse_geosite(payload: bytes) -> tuple[str, list[tuple[int, str]]]:
    buf = memoryview(payload)
    index = 0
    code = ""
    domains: list[tuple[int, str]] = []
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise GeoDataError("invalid protobuf field number")
        if field_number == 1 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            code = _decode_text(raw, "category code")
            continue
        if field_number == 2 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            domains.append(_parse_domain(raw))
            continue
        index = _skip(buf, index, wire_type)
    return code, domains


def parse_geoip_list(payload: bytes) -> list[tuple[str, bool, list[tuple[bytes, int]]]]:
    """Decode a GeoIPList message into (country, inverse_match, cidrs)."""
    buf = memoryview(payload)
    index = 0
    entries = []
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise GeoDataError("invalid protobuf field number")
        if field_number == 1 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            entries.append(_parse_geoip(raw))
            continue
        index = _skip(buf, index, wire_type)
    return entries


def parse_geosite_list(payload: bytes) -> list[tuple[str, list[tuple[int, str]]]]:
    """Decode a GeoSiteList message into (category, domain rules)."""
    buf = memoryview(payload)
    index = 0
    entries = []
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise GeoDataError("invalid protobuf field number")
        if field_number == 1 and wire_type == 2:
            raw, index = _take_bytes(buf, index)
            entries.append(_parse_geosite(raw))
            continue
        index = _skip(buf, index, wire_type)
    return entries


def _v4_bounds(raw: bytes, prefix: int) -> tuple[int, int]:
    if len(raw) != 4 or not 0 <= prefix <= 32:
        raise GeoDataError("invalid IPv4 CIDR")
    start = int.from_bytes(raw, "big")
    if prefix == 0:
        mask = 0
    else:
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = start & mask
    size = 1 << (32 - prefix)
    return network, network + size - 1


def _v6_bounds(raw: bytes, prefix: int) -> tuple[int, int]:
    if len(raw) != 16 or not 0 <= prefix <= 128:
        raise GeoDataError("invalid IPv6 CIDR")
    start = int.from_bytes(raw, "big")
    if prefix == 0:
        mask = 0
    else:
        mask = ((1 << 128) - 1) << (128 - prefix)
        mask &= (1 << 128) - 1
    network = start & mask
    size = 1 << (128 - prefix)
    return network, network + size - 1


def _as_v4(raw: bytes, prefix: int) -> tuple[bytes, int] | None:
    """Return an IPv4 CIDR when the address is 4 bytes or a v4-mapped CIDR."""
    if len(raw) == 4:
        return raw, prefix
    if len(raw) == 16 and raw[:12] == _V4_MAPPED_PREFIX and prefix >= 96:
        return raw[12:], prefix - 96
    return None


class _IpIndex:
    """First-match-friendly CIDR index. Results are returned in file order."""

    def __init__(self) -> None:
        self.codes: list[str] = []
        self._v4_16: dict[int, list[tuple[int, int, int]]] = {}
        self._v4_8: dict[int, list[tuple[int, int, int]]] = {}
        self._v4_wide: list[tuple[int, int, int]] = []
        self._v6_16: dict[int, list[tuple[int, int, int]]] = {}
        self._v6_wide: list[tuple[int, int, int]] = []
        self._inverse: list[tuple[int, list[tuple[str, int, int]]]] = []

    def add(self, code: str, inverse: bool, cidrs: list[tuple[bytes, int]]) -> None:
        index = len(self.codes)
        self.codes.append(code)
        parsed: list[tuple[str, int, int]] = []
        for raw, prefix in cidrs:
            mapped = _as_v4(raw, prefix)
            if mapped is not None:
                address, bits = mapped
                start, end = _v4_bounds(address, bits)
                parsed.append(("v4", start, end))
                if not inverse:
                    self._store_v4(start, end, bits, index)
                continue
            start, end = _v6_bounds(raw, prefix)
            parsed.append(("v6", start, end))
            if not inverse:
                self._store_v6(start, end, prefix, index)
        if inverse:
            self._inverse.append((index, parsed))

    def _store_v4(self, start: int, end: int, prefix: int, index: int) -> None:
        item = (start, end, index)
        if prefix >= 16:
            self._v4_16.setdefault(start >> 16, []).append(item)
        elif prefix >= 8:
            self._v4_8.setdefault(start >> 24, []).append(item)
        else:
            self._v4_wide.append(item)

    def _store_v6(self, start: int, end: int, prefix: int, index: int) -> None:
        item = (start, end, index)
        if prefix >= 16:
            self._v6_16.setdefault(start >> 112, []).append(item)
        else:
            self._v6_wide.append(item)

    def lookup(self, ip_text: str) -> list[str]:
        try:
            address = ipaddress.ip_address(ip_text.strip())
        except ValueError as exc:
            raise GeoDataError(f"invalid IP address: {ip_text!r}") from exc
        matched: set[int] = set()
        if isinstance(address, ipaddress.IPv4Address):
            self._collect_v4(int(address), matched)
        else:
            mapped = address.ipv4_mapped
            if mapped is not None:
                self._collect_v4(int(mapped), matched)
            self._collect_v6(int(address), matched)
        self._collect_inverse(address, matched)
        return [self.codes[index] for index in sorted(matched)]

    def _collect_v4(self, ip_int: int, matched: set[int]) -> None:
        candidates: list[tuple[int, int, int]] = []
        candidates.extend(self._v4_16.get(ip_int >> 16, ()))
        candidates.extend(self._v4_8.get(ip_int >> 24, ()))
        candidates.extend(self._v4_wide)
        for start, end, index in candidates:
            if start <= ip_int <= end:
                matched.add(index)

    def _collect_v6(self, ip_int: int, matched: set[int]) -> None:
        candidates = self._v6_16.get(ip_int >> 112, ())
        for start, end, index in candidates:
            if start <= ip_int <= end:
                matched.add(index)
        for start, end, index in self._v6_wide:
            if start <= ip_int <= end:
                matched.add(index)

    def _collect_inverse(self, address, matched: set[int]) -> None:
        for index, cidrs in self._inverse:
            hit = False
            for family, start, end in cidrs:
                if family == "v4" and isinstance(address, ipaddress.IPv4Address):
                    ip_int = int(address)
                elif family == "v4" and getattr(address, "ipv4_mapped", None) is not None:
                    ip_int = int(address.ipv4_mapped)
                elif family == "v6" and isinstance(address, ipaddress.IPv6Address):
                    ip_int = int(address)
                else:
                    continue
                if start <= ip_int <= end:
                    hit = True
                    break
            if not hit:
                matched.add(index)


def _ascii_domain(value: str) -> str:
    text = value.strip().lower().strip(".")
    if not text:
        return ""
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return text


class _DomainIndex:
    def __init__(self) -> None:
        self.codes: list[str] = []
        self.skipped_rules = 0
        self._full: dict[str, list[int]] = {}
        self._root: dict[str, list[int]] = {}
        self._plain: list[tuple[str, int]] = []
        self._regex: list[tuple[re.Pattern[str], int]] = []

    def add(self, code: str, rules: list[tuple[int, str]]) -> None:
        index = len(self.codes)
        self.codes.append(code)
        for domain_type, value in rules:
            if domain_type not in (0, 1, 2, 3):
                self.skipped_rules += 1
                continue
            if domain_type == 1:
                self._add_regex(value, index)
                continue
            normalized = _ascii_domain(value)
            if not normalized:
                self.skipped_rules += 1
                continue
            if domain_type == 0:
                self._plain.append((normalized, index))
            elif domain_type == 3:
                self._append(self._full, normalized, index)
            else:
                self._append(self._root, normalized, index)

    def _add_regex(self, pattern: str, index: int) -> None:
        if not pattern or len(pattern) > _MAX_REGEX_LENGTH:
            self.skipped_rules += 1
            return
        try:
            compiled = re.compile(pattern)
        except re.error:
            self.skipped_rules += 1
            return
        self._regex.append((compiled, index))

    @staticmethod
    def _append(mapping: dict[str, list[int]], key: str, index: int) -> None:
        bucket = mapping.get(key)
        if bucket is None:
            mapping[key] = [index]
        elif index not in bucket:
            bucket.append(index)

    def lookup(self, domain: str) -> list[str]:
        raw = domain.strip().lower().strip(".")
        if not raw:
            return []
        ascii_domain = _ascii_domain(raw)
        matched: list[int] = []
        seen: set[int] = set()

        def add(index: int) -> None:
            if index not in seen:
                seen.add(index)
                matched.append(index)

        for index in self._full.get(ascii_domain, ()):
            add(index)
        labels = ascii_domain.split(".")
        for start in range(len(labels)):
            suffix = ".".join(labels[start:])
            for index in self._root.get(suffix, ()):
                add(index)
        for keyword, index in self._plain:
            if keyword in ascii_domain:
                add(index)
        subjects = [raw] if raw == ascii_domain else [raw, ascii_domain]
        for pattern, index in self._regex:
            if any(pattern.search(subject) for subject in subjects):
                add(index)
        return [self.codes[index] for index in matched]


class GeoDataset:
    """In-memory geoip and geosite data."""

    def __init__(
        self,
        ip_index: _IpIndex,
        domain_index: _DomainIndex,
    ) -> None:
        self._ip_index = ip_index
        self._domain_index = domain_index

    @classmethod
    def from_bytes(cls, geoip: bytes, geosite: bytes) -> GeoDataset:
        ip_index = _IpIndex()
        for code, inverse, cidrs in parse_geoip_list(geoip):
            ip_index.add(code, inverse, cidrs)
        domain_index = _DomainIndex()
        for code, rules in parse_geosite_list(geosite):
            domain_index.add(code, rules)
        return cls(ip_index, domain_index)

    @classmethod
    def from_files(cls, geoip_path: Path | str, geosite_path: Path | str) -> GeoDataset:
        return cls.from_bytes(
            Path(geoip_path).read_bytes(),
            Path(geosite_path).read_bytes(),
        )

    @property
    def ip_entry_count(self) -> int:
        return len(self._ip_index.codes)

    @property
    def site_entry_count(self) -> int:
        return len(self._domain_index.codes)

    @property
    def skipped_rules(self) -> int:
        return self._domain_index.skipped_rules

    def lookup_ip(self, ip: str) -> list[str]:
        """Return country codes whose CIDR sets match ``ip``, in file order."""
        if ip is None or not str(ip).strip():
            return []
        return self._ip_index.lookup(str(ip))

    def lookup_domain(self, domain: str) -> list[str]:
        """Return category codes that match ``domain``, in file order.

        Full, root-domain, and keyword rules are compared case-insensitively
        after IDNA conversion. Regex rules are case-sensitive and run against
        the lowercased domain, matching v2ray's regexp matcher.
        """
        if domain is None or not str(domain).strip():
            return []
        return self._domain_index.lookup(str(domain))
