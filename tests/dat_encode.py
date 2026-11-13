"""Tiny protobuf encoder for synthetic v2ray geo fixtures."""

from __future__ import annotations


def varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative varint")
    out = bytearray()
    while True:
        piece = value & 0x7F
        value >>= 7
        if value:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def length_field(field: int, payload: bytes) -> bytes:
    return varint((field << 3) | 2) + varint(len(payload)) + payload


def varint_field(field: int, value: int) -> bytes:
    return varint((field << 3) | 0) + varint(value)


def encode_cidr(ip: bytes, prefix: int) -> bytes:
    return length_field(1, ip) + varint_field(2, prefix)


def encode_geoip_entry(code: str, cidrs: list[tuple[bytes, int]], inverse: bool = False) -> bytes:
    body = length_field(1, code.encode("utf-8"))
    for ip, prefix in cidrs:
        body += length_field(2, encode_cidr(ip, prefix))
    if inverse:
        body += varint_field(3, 1)
    return body


def encode_geoip_list(entries: list[tuple]) -> bytes:
    body = b""
    for entry in entries:
        code, cidrs = entry[0], entry[1]
        inverse = bool(entry[2]) if len(entry) > 2 else False
        body += length_field(1, encode_geoip_entry(code, cidrs, inverse))
    return body


def encode_domain(value: str, domain_type: int = 0, attributes: list[dict] | None = None) -> bytes:
    body = b""
    if domain_type:
        body += varint_field(1, domain_type)
    body += length_field(2, value.encode("utf-8"))
    for attribute in attributes or []:
        attr = length_field(1, attribute["key"].encode("utf-8"))
        if "bool" in attribute:
            attr += varint_field(2, 1 if attribute["bool"] else 0)
        if "int" in attribute:
            attr += varint_field(3, attribute["int"])
        body += length_field(3, attr)
    return body


def encode_geosite_list(sites: list[dict]) -> bytes:
    body = b""
    for site in sites:
        payload = length_field(1, site["code"].encode("utf-8"))
        for domain in site["domains"]:
            payload += length_field(2, encode_domain(**domain))
        body += length_field(1, payload)
    return body


def sample_geoip() -> bytes:
    return encode_geoip_list(
        [
            ("US", [(bytes([192, 0, 2, 0]), 24), (bytes.fromhex("20010db8" + "00" * 12), 32)]),
            ("CN", [(bytes([198, 51, 100, 0]), 25)]),
            ("PRIVATE", [(bytes([10, 0, 0, 0]), 8)]),
            (
                "MAP",
                [(b"\x00" * 10 + b"\xff\xff" + bytes([203, 0, 113, 0]), 120)],
            ),
            ("ZZ", [(bytes([203, 0, 113, 0]), 24)], True),
        ]
    )


def sample_geosite() -> bytes:
    return encode_geosite_list(
        [
            {
                "code": "google",
                "domains": [
                    {"value": "google.com", "domain_type": 2, "attributes": [{"key": "cn", "bool": False}]},
                ],
            },
            {"code": "ads", "domains": [{"value": "doubleclick", "domain_type": 0}]},
            {"code": "exact", "domains": [{"value": "exact.example", "domain_type": 3}]},
            {"code": "news", "domains": [{"value": r"^news\.example$", "domain_type": 1}]},
            {"code": "broken", "domains": [{"value": "(", "domain_type": 1}]},
            {"code": "idn", "domains": [{"value": "bücher.example", "domain_type": 2}]},
        ]
    )
