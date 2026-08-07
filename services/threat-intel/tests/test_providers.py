"""Stage B verification: each connector's normalization logic, tested
against mocked HTTP responses (deterministic, no live network dependency),
plus a fault-isolation test proving one provider's failure never affects
the others.
"""
import httpx
import pytest
import respx

from app.provider.abuseipdb import AbuseIpdbProvider
from app.provider.base import PROVIDER_REGISTRY
from app.provider.cisa_kev import CisaKevProvider
from app.provider.emerging_threats import EmergingThreatsProvider
from app.provider.nvd_cve import NvdCveProvider
from app.provider.otx import OtxProvider
from app.provider.spamhaus_drop import SpamhausDropProvider
from app.provider.threatfox import ThreatFoxProvider
from app.settings import Settings

pytestmark = pytest.mark.asyncio


def make_settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


async def test_registry_has_all_seven_providers():
    names = {p().name for p in PROVIDER_REGISTRY}
    assert names == {
        "threatfox",
        "cisa_kev",
        "spamhaus_drop",
        "emerging_threats",
        "nvd_cve",
        "abuseipdb",
        "otx",
    }


async def test_no_key_providers_enabled_by_default():
    settings = make_settings()
    for provider_cls in (ThreatFoxProvider, CisaKevProvider, SpamhausDropProvider, EmergingThreatsProvider, NvdCveProvider):
        assert provider_cls().is_enabled(settings) is True


async def test_key_gated_providers_disabled_without_key():
    settings = make_settings(ABUSEIPDB_API_KEY="", OTX_API_KEY="")
    assert AbuseIpdbProvider().is_enabled(settings) is False
    assert OtxProvider().is_enabled(settings) is False


async def test_key_gated_providers_enabled_with_key():
    settings = make_settings(ABUSEIPDB_API_KEY="dummy-key", OTX_API_KEY="dummy-key")
    assert AbuseIpdbProvider().is_enabled(settings) is True
    assert OtxProvider().is_enabled(settings) is True


async def test_key_gated_provider_fetch_is_a_noop_without_key():
    """Even if something calls fetch() on a disabled provider by mistake,
    it must not attempt a request or raise -- it just returns []."""
    settings = make_settings(ABUSEIPDB_API_KEY="", OTX_API_KEY="")
    async with httpx.AsyncClient() as client:
        assert await AbuseIpdbProvider().fetch(client, settings) == []
        assert await OtxProvider().fetch(client, settings) == []


@respx.mock
async def test_threatfox_normalizes_ip_port_iocs():
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "1.2.3.4:8080",
                        "ioc_type": "ip:port",
                        "threat_type": "botnet_cc",
                        "threat_type_desc": "Botnet C2",
                        "confidence_level": 80,
                        "last_seen": "2026-07-14 10:00:00 UTC",
                        "malware_printable": "Cobalt Strike",
                    },
                    {"ioc": "evil.example.com", "ioc_type": "domain"},  # non-IP, must be skipped
                ],
            },
        )
    )
    async with httpx.AsyncClient() as client:
        events = await ThreatFoxProvider().fetch(client, make_settings())
    assert len(events) == 1
    assert events[0].ioc == "1.2.3.4"
    assert events[0].threat_type == "botnet_cc"
    assert events[0].attack_family == "Cobalt Strike"
    assert events[0].confidence_score == pytest.approx(0.8)


@respx.mock
async def test_threatfox_returns_empty_on_http_error():
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(return_value=httpx.Response(500))
    async with httpx.AsyncClient() as client:
        events = await ThreatFoxProvider().fetch(client, make_settings())
    assert events == []


@respx.mock
async def test_cisa_kev_normalizes_to_cve_events():
    respx.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-0001",
                        "vendorProject": "Acme",
                        "product": "Widget",
                        "shortDescription": "Remote code execution",
                        "dateAdded": "2026-07-01",
                    }
                ]
            },
        )
    )
    async with httpx.AsyncClient() as client:
        events = await CisaKevProvider().fetch(client, make_settings())
    assert len(events) == 1
    assert events[0].cve_id == "CVE-2026-0001"
    assert events[0].vendor_project == "Acme"


@respx.mock
async def test_spamhaus_drop_parses_cidr_lines():
    body = "; comment line\n185.220.101.0/24 ; SBL401831\nnot-a-cidr-line\n"
    respx.get("https://www.spamhaus.org/drop/drop.txt").mock(return_value=httpx.Response(200, text=body))
    respx.get("https://www.spamhaus.org/drop/edrop.txt").mock(return_value=httpx.Response(200, text=""))
    async with httpx.AsyncClient() as client:
        events = await SpamhausDropProvider().fetch(client, make_settings())
    assert len(events) == 1
    assert events[0].ioc == "185.220.101.0/24"
    assert events[0].ioc_type == "cidr"


@respx.mock
async def test_emerging_threats_parses_ip_list():
    body = "# comment\n1.2.3.4\n5.6.7.8\nnot-an-ip\n"
    respx.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt").mock(
        return_value=httpx.Response(200, text=body)
    )
    async with httpx.AsyncClient() as client:
        events = await EmergingThreatsProvider().fetch(client, make_settings())
    assert {e.ioc for e in events} == {"1.2.3.4", "5.6.7.8"}


@respx.mock
async def test_nvd_cve_extracts_severity_and_description():
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-1234",
                            "descriptions": [{"lang": "en", "value": "A bug"}],
                            "published": "2026-07-13T00:00:00.000",
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                        }
                    }
                ]
            },
        )
    )
    async with httpx.AsyncClient() as client:
        events = await NvdCveProvider().fetch(client, make_settings())
    assert len(events) == 1
    assert events[0].severity == "HIGH"
    assert events[0].description == "A bug"


@respx.mock
async def test_abuseipdb_disabled_returns_empty_and_makes_no_request():
    route = respx.get("https://api.abuseipdb.com/api/v2/blacklist")
    async with httpx.AsyncClient() as client:
        events = await AbuseIpdbProvider().fetch(client, make_settings(ABUSEIPDB_API_KEY=""))
    assert events == []
    assert route.call_count == 0


@respx.mock
async def test_abuseipdb_enabled_normalizes_blacklist():
    respx.get("https://api.abuseipdb.com/api/v2/blacklist").mock(
        return_value=httpx.Response(200, json={"data": [{"ipAddress": "9.9.9.9", "abuseConfidenceScore": 95}]})
    )
    async with httpx.AsyncClient() as client:
        events = await AbuseIpdbProvider().fetch(client, make_settings(ABUSEIPDB_API_KEY="dummy"))
    assert len(events) == 1
    assert events[0].ioc == "9.9.9.9"
    assert events[0].confidence_score == pytest.approx(0.95)


@respx.mock
async def test_otx_normalizes_ipv4_indicators_only():
    respx.get("https://otx.alienvault.com/api/v1/pulses/subscribed").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "name": "Campaign X",
                        "created": "2026-07-14T00:00:00",
                        "tags": ["botnet"],
                        "malware_families": ["Emotet"],
                        "indicators": [
                            {"indicator": "4.4.4.4", "type": "IPv4"},
                            {"indicator": "evil.example.com", "type": "domain"},
                        ],
                    }
                ]
            },
        )
    )
    async with httpx.AsyncClient() as client:
        events = await OtxProvider().fetch(client, make_settings(OTX_API_KEY="dummy"))
    assert len(events) == 1
    assert events[0].ioc == "4.4.4.4"
    assert events[0].attack_family == "Emotet"


@respx.mock
async def test_one_provider_failing_does_not_affect_others():
    """Simulates ThreatFox being completely down (connection error) while
    every other no-key provider succeeds -- proves a single provider outage
    can't cascade, since each connector catches its own errors internally.
    """
    respx.post("https://threatfox-api.abuse.ch/api/v1/").mock(side_effect=httpx.ConnectError("simulated outage"))
    respx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2026-9999", "dateAdded": "2026-07-01"}]})
    )
    respx.get("https://www.spamhaus.org/drop/drop.txt").mock(return_value=httpx.Response(200, text="1.2.3.0/24 ; SBL1\n"))
    respx.get("https://www.spamhaus.org/drop/edrop.txt").mock(return_value=httpx.Response(200, text=""))
    respx.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt").mock(
        return_value=httpx.Response(200, text="6.6.6.6\n")
    )
    respx.get("https://services.nvd.nist.gov/rest/json/cves/2.0").mock(return_value=httpx.Response(200, json={"vulnerabilities": []}))

    settings = make_settings()
    results = {}
    async with httpx.AsyncClient() as client:
        for provider_cls in (
            ThreatFoxProvider,
            CisaKevProvider,
            SpamhausDropProvider,
            EmergingThreatsProvider,
            NvdCveProvider,
        ):
            provider = provider_cls()
            # No try/except here on purpose: if a connector let an exception
            # escape, this loop would abort and the assertions below would
            # never run -- the test itself is the proof of fault isolation.
            results[provider.name] = await provider.fetch(client, settings)

    assert results["threatfox"] == []  # failed provider degrades to empty, doesn't raise
    assert len(results["cisa_kev"]) == 1  # every other provider still produced data
    assert len(results["spamhaus_drop"]) == 1
    assert len(results["emerging_threats"]) == 1
    assert results["nvd_cve"] == []
