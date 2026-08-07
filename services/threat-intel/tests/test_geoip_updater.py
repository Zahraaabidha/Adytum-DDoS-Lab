"""Verifies the GeoLite2 updater self-disables without a license key, and
correctly downloads+extracts a .mmdb from a mocked tar.gz response when a
key is present -- without hitting the real MaxMind API.
"""
import io
import tarfile

import httpx
import pytest
import respx

from app.geoip_updater import run_update_cycle
from app.settings import Settings

pytestmark = pytest.mark.asyncio


def make_settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def _make_tarball(mmdb_name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=f"GeoLite2-City_20260714/{mmdb_name}")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


async def test_no_license_key_does_not_attempt_any_download(tmp_path):
    route = respx.get("https://download.maxmind.com/app/geoip_download")
    with respx.mock:
        await run_update_cycle(make_settings(MAXMIND_LICENSE_KEY="", GEOIP_DB_DIR=str(tmp_path)))
        assert route.call_count == 0
    assert list(tmp_path.glob("*.mmdb")) == []


@respx.mock
async def test_download_and_extract_with_valid_key(tmp_path):
    city_tar = _make_tarball("GeoLite2-City.mmdb", b"fake-city-mmdb-bytes")
    asn_tar = _make_tarball("GeoLite2-ASN.mmdb", b"fake-asn-mmdb-bytes")

    def responder(request: httpx.Request) -> httpx.Response:
        edition = request.url.params.get("edition_id")
        if edition == "GeoLite2-City":
            return httpx.Response(200, content=city_tar)
        return httpx.Response(200, content=asn_tar)

    respx.get("https://download.maxmind.com/app/geoip_download").mock(side_effect=responder)

    await run_update_cycle(make_settings(MAXMIND_LICENSE_KEY="dummy-key", GEOIP_DB_DIR=str(tmp_path)))

    city_path = tmp_path / "GeoLite2-City.mmdb"
    asn_path = tmp_path / "GeoLite2-ASN.mmdb"
    assert city_path.exists()
    assert city_path.read_bytes() == b"fake-city-mmdb-bytes"
    assert asn_path.exists()
    assert asn_path.read_bytes() == b"fake-asn-mmdb-bytes"
    # no leftover .tmp files after the atomic rename
    assert list(tmp_path.glob("*.tmp")) == []


@respx.mock
async def test_one_edition_failing_does_not_block_the_other(tmp_path):
    asn_tar = _make_tarball("GeoLite2-ASN.mmdb", b"fake-asn-mmdb-bytes")

    def responder(request: httpx.Request) -> httpx.Response:
        edition = request.url.params.get("edition_id")
        if edition == "GeoLite2-City":
            return httpx.Response(401, text="invalid license key")
        return httpx.Response(200, content=asn_tar)

    respx.get("https://download.maxmind.com/app/geoip_download").mock(side_effect=responder)

    await run_update_cycle(make_settings(MAXMIND_LICENSE_KEY="dummy-key", GEOIP_DB_DIR=str(tmp_path)))

    assert not (tmp_path / "GeoLite2-City.mmdb").exists()
    assert (tmp_path / "GeoLite2-ASN.mmdb").exists()
