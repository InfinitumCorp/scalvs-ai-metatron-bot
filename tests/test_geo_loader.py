"""Decoder tests use hand-built protobuf bytes plus synthetic fixtures."""

from __future__ import annotations

import unittest
from pathlib import Path

from scalvs_metatron.geo_loader import GeoDataError, GeoDataset
from tests.dat_encode import sample_geoip, sample_geosite

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# GeoIPList { entry: GeoIP { country_code: "US", cidr: { ip: 192.0.2.0, prefix: 24 } } }
US_GEOIP = bytes.fromhex("0a0e0a02555312080a04c00002001018")
# GeoIPList { entry: GeoIP { country_code: "ZZ", cidr: 192.0.2.0/24, inverse_match: true } }
INVERSE_GEOIP = bytes.fromhex("0a100a025a5a12080a04c000020010181801")
# GeoSiteList { entry: GeoSite { country_code: "ex", domain: { type: RootDomain, value: "a.test" } } }
ROOT_GEOSITE = bytes.fromhex("0a100a026578120a08021206612e74657374")
# GeoSiteList { entry: GeoSite { country_code: "ads", domain: { value: "ads" } } }  type omitted = Plain
PLAIN_GEOSITE = bytes.fromhex("0a0c0a0361647312051203616473")


class HandBuiltProtobufTest(unittest.TestCase):
    def test_ipv4_country_lookup(self) -> None:
        dataset = GeoDataset.from_bytes(US_GEOIP, b"")
        self.assertEqual(dataset.lookup_ip("192.0.2.1"), ["US"])
        self.assertEqual(dataset.lookup_ip("192.0.2.0"), ["US"])
        self.assertEqual(dataset.lookup_ip("192.0.2.255"), ["US"])
        self.assertEqual(dataset.lookup_ip("192.0.3.1"), [])

    def test_inverse_match(self) -> None:
        dataset = GeoDataset.from_bytes(INVERSE_GEOIP, b"")
        self.assertEqual(dataset.lookup_ip("192.0.2.1"), [])
        self.assertEqual(dataset.lookup_ip("198.51.100.1"), ["ZZ"])

    def test_root_domain_lookup(self) -> None:
        dataset = GeoDataset.from_bytes(b"", ROOT_GEOSITE)
        self.assertEqual(dataset.lookup_domain("a.test"), ["ex"])
        self.assertEqual(dataset.lookup_domain("WWW.A.TEST."), ["ex"])
        self.assertEqual(dataset.lookup_domain("b.a.test"), ["ex"])
        self.assertEqual(dataset.lookup_domain("nota.test"), [])
        self.assertEqual(dataset.lookup_domain("a.test.com"), [])

    def test_plain_domain_defaults_when_type_omitted(self) -> None:
        dataset = GeoDataset.from_bytes(b"", PLAIN_GEOSITE)
        self.assertEqual(dataset.lookup_domain("xxadsyy.example"), ["ads"])
        self.assertEqual(dataset.lookup_domain("example.com"), [])

    def test_truncated_and_unknown_wire_type(self) -> None:
        with self.assertRaises(GeoDataError):
            GeoDataset.from_bytes(bytes.fromhex("0a"), b"")
        with self.assertRaises(GeoDataError):
            GeoDataset.from_bytes(bytes([0x0F]), b"")

    def test_invalid_ip(self) -> None:
        dataset = GeoDataset.from_bytes(US_GEOIP, b"")
        with self.assertRaises(GeoDataError):
            dataset.lookup_ip("not-an-ip")


class SyntheticFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dataset = GeoDataset.from_bytes(sample_geoip(), sample_geosite())

    def test_committed_fixtures_match_the_encoder(self) -> None:
        self.assertEqual((FIXTURES / "geoip.dat").read_bytes(), sample_geoip())
        self.assertEqual((FIXTURES / "geosite.dat").read_bytes(), sample_geosite())

    def test_country_and_private_ranges(self) -> None:
        dataset = self.dataset
        self.assertEqual(dataset.lookup_ip("192.0.2.20"), ["US", "ZZ"])
        self.assertEqual(dataset.lookup_ip("198.51.100.10"), ["CN", "ZZ"])
        self.assertEqual(dataset.lookup_ip("198.51.100.200"), ["ZZ"])
        self.assertEqual(dataset.lookup_ip("10.1.2.3"), ["PRIVATE", "ZZ"])
        self.assertEqual(dataset.lookup_ip("2001:db8::1"), ["US", "ZZ"])
        self.assertEqual(dataset.lookup_ip("203.0.113.9"), ["MAP"])
        self.assertEqual(dataset.lookup_ip("::ffff:203.0.113.9"), ["MAP"])

    def test_domain_categories(self) -> None:
        dataset = self.dataset
        self.assertEqual(dataset.lookup_domain("mail.google.com"), ["google"])
        self.assertEqual(dataset.lookup_domain("notgoogle.com"), [])
        self.assertEqual(dataset.lookup_domain("ads.doubleclick.net"), ["ads"])
        self.assertEqual(dataset.lookup_domain("exact.example"), ["exact"])
        self.assertEqual(dataset.lookup_domain("www.exact.example"), [])
        self.assertEqual(dataset.lookup_domain("news.example"), ["news"])
        self.assertEqual(dataset.lookup_domain("other.news.example"), [])
        self.assertEqual(dataset.lookup_domain("www.bücher.example"), ["idn"])
        self.assertEqual(dataset.lookup_domain("www.xn--bcher-kva.example"), ["idn"])
        self.assertEqual(dataset.skipped_rules, 1)

    def test_files_round_trip(self) -> None:
        loaded = GeoDataset.from_files(FIXTURES / "geoip.dat", FIXTURES / "geosite.dat")
        self.assertEqual(loaded.lookup_ip("10.9.8.7"), ["PRIVATE", "ZZ"])
        self.assertEqual(loaded.ip_entry_count, 5)
        self.assertEqual(loaded.site_entry_count, 6)
