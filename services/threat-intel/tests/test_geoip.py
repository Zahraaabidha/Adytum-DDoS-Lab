"""Stage C.5 verification: GeoIP enrichment against real (test-fixture)
MaxMind .mmdb files -- not mocks of geoip2's internals -- plus the
self-disable behavior when no database is present.
"""
from pathlib import Path

import pytest

from app.common.geoip import GeoIpEnricher
from app.settings import Settings

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_lookup_resolves_with_correctly_named_fixture(tmp_path, monkeypatch):
    import shutil

    shutil.copy(FIXTURES_DIR / "GeoLite2-City-Test.mmdb", tmp_path / "GeoLite2-City.mmdb")
    shutil.copy(FIXTURES_DIR / "GeoLite2-ASN-Test.mmdb", tmp_path / "GeoLite2-ASN.mmdb")
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    enricher = GeoIpEnricher()
    assert enricher.is_available() is True

    result = enricher.lookup("8.8.8.8")
    assert result is not None
    assert result.country == "US"
    assert result.city == "Mountain View"
    assert result.lat == pytest.approx(37.386)
    assert result.lon == pytest.approx(-122.0838)
    assert result.asn == 15169
    assert result.organization == "GOOGLE"
    assert result.source == "geolite2"


def test_lookup_unmatched_ip_returns_none_not_raise(tmp_path, monkeypatch):
    import shutil

    shutil.copy(FIXTURES_DIR / "GeoLite2-City-Test.mmdb", tmp_path / "GeoLite2-City.mmdb")
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    enricher = GeoIpEnricher()
    assert enricher.lookup("203.0.113.99") is None  # not in the tiny test fixture


def test_lookup_private_address_never_geolocated(tmp_path, monkeypatch):
    import shutil

    shutil.copy(FIXTURES_DIR / "GeoLite2-City-Test.mmdb", tmp_path / "GeoLite2-City.mmdb")
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    enricher = GeoIpEnricher()
    assert enricher.lookup("10.0.0.5") is None
    assert enricher.lookup("127.0.0.1") is None


def test_city_db_missing_disables_enrichment(tmp_path, monkeypatch):
    """Empty directory -- no MAXMIND_LICENSE_KEY was ever set, so the
    updater never produced a file. Must degrade cleanly, never raise."""
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    enricher = GeoIpEnricher()
    assert enricher.is_available() is False
    assert enricher.lookup("8.8.8.8") is None


def test_city_db_present_but_asn_db_missing_still_enriches_city(tmp_path, monkeypatch):
    """ASN is a bonus, not a requirement -- country/city/lat/lon still
    work with only the City database present."""
    import shutil

    shutil.copy(FIXTURES_DIR / "GeoLite2-City-Test.mmdb", tmp_path / "GeoLite2-City.mmdb")
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    enricher = GeoIpEnricher()
    result = enricher.lookup("8.8.8.8")
    assert result is not None
    assert result.country == "US"
    assert result.asn is None
    assert result.organization is None


@pytest.mark.parametrize(
    "address",
    ["10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "240.0.0.1", "224.0.0.1", "::1", "fe80::1", "not-an-ip", ""],
)
def test_non_public_or_invalid_addresses_are_never_looked_up(tmp_path, monkeypatch, address):
    import shutil

    shutil.copy(FIXTURES_DIR / "GeoLite2-City-Test.mmdb", tmp_path / "GeoLite2-City.mmdb")
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    assert GeoIpEnricher().lookup(address) is None


def test_status_reports_what_is_actually_loaded(tmp_path, monkeypatch):
    import shutil

    shutil.copy(FIXTURES_DIR / "GeoLite2-City-Test.mmdb", tmp_path / "GeoLite2-City.mmdb")
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    status = GeoIpEnricher().status()
    assert status["city_db_loaded"] is True
    assert status["asn_db_loaded"] is False
    assert status["city_db_build_date"] is not None
    assert status["asn_db_build_date"] is None


def test_status_with_no_databases(tmp_path, monkeypatch):
    monkeypatch.setattr("app.common.geoip.get_settings", lambda: make_settings(GEOIP_DB_DIR=str(tmp_path)))

    status = GeoIpEnricher().status()
    assert status == {
        "city_db_loaded": False,
        "asn_db_loaded": False,
        "city_db_build_date": None,
        "asn_db_build_date": None,
    }
