import json
from unittest.mock import AsyncMock, patch

import httpx
import respx

from mail_sovereignty.preprocess import (
    fetch_wikidata,
    guess_domains,
    run,
    scan_municipality,
    url_to_domain,
)


# ── url_to_domain() ─────────────────────────────────────────────────


class TestUrlToDomain:
    def test_full_url_with_path(self):
        assert url_to_domain("https://www.koeln.de/some/path") == "koeln.de"

    def test_no_scheme(self):
        assert url_to_domain("koeln.de") == "koeln.de"

    def test_strips_www(self):
        assert url_to_domain("https://www.example.de") == "example.de"

    def test_empty_string(self):
        assert url_to_domain("") is None

    def test_none(self):
        assert url_to_domain(None) is None

    def test_bare_domain(self):
        assert url_to_domain("example.de") == "example.de"

    def test_http_scheme(self):
        assert url_to_domain("http://example.de/page") == "example.de"


# ── guess_domains() ─────────────────────────────────────────────────


class TestGuessDomains:
    def test_simple_name(self):
        domains = guess_domains("München")
        assert "muenchen.de" in domains
        assert "gemeinde-muenchen.de" in domains
        assert "stadt-muenchen.de" in domains

    def test_umlaut(self):
        domains = guess_domains("Zürich")
        assert "zuerich.de" in domains

    def test_eszett(self):
        domains = guess_domains("Großenhain")
        assert "grossenhain.de" in domains

    def test_parenthetical_stripped(self):
        domains = guess_domains("Neustadt (Dosse)")
        assert any("neustadt" in d for d in domains)
        assert not any("Dosse" in d for d in domains)

    def test_stadt_prefix(self):
        domains = guess_domains("München")
        assert "stadt-muenchen.de" in domains

    def test_vg_prefix(self):
        domains = guess_domains("Westerburg")
        assert "vg-westerburg.de" in domains

    def test_samtgemeinde_prefix(self):
        domains = guess_domains("Artland")
        assert "samtgemeinde-artland.de" in domains

    def test_markt_prefix(self):
        domains = guess_domains("Oberkotzau")
        assert "markt-oberkotzau.de" in domains

    def test_apostrophe_removed(self):
        domains = guess_domains("L'Abbaye")
        assert any("abbaye" in d for d in domains)


# ── fetch_wikidata() ─────────────────────────────────────────────────


class TestFetchWikidata:
    @respx.mock
    async def test_success(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "ags": {"value": "05315000"},
                                "itemLabel": {"value": "Köln"},
                                "website": {"value": "https://www.stadt-koeln.de"},
                                "stateLabel": {"value": "Nordrhein-Westfalen"},
                                "districtLabel": {"value": "Köln"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert "05315000" in result
        assert result["05315000"]["name"] == "Köln"
        assert result["05315000"]["state"] == "Nordrhein-Westfalen"

    @respx.mock
    async def test_deduplication(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "ags": {"value": "05315000"},
                                "itemLabel": {"value": "Köln"},
                                "website": {"value": "https://www.stadt-koeln.de"},
                                "stateLabel": {"value": "Nordrhein-Westfalen"},
                            },
                            {
                                "ags": {"value": "05315000"},
                                "itemLabel": {"value": "Köln"},
                                "website": {"value": "https://www.koeln.de"},
                                "stateLabel": {"value": "Nordrhein-Westfalen"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert len(result) == 1


# ── scan_municipality() ──────────────────────────────────────────────


class TestScanMunicipality:
    async def test_website_domain_mx_found(self):
        m = {
            "ags": "05315000",
            "name": "Köln",
            "state": "Nordrhein-Westfalen",
            "website": "https://www.stadt-koeln.de",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["domain"] == "stadt-koeln.de"

    async def test_no_website_guesses_domain(self):
        m = {"ags": "99999999", "name": "Köln", "state": "NRW", "website": ""}
        sem = __import__("asyncio").Semaphore(10)

        async def fake_lookup_mx(domain):
            if domain == "koeln.de":
                return ["mail.koeln.de"]
            return []

        with (
            patch("mail_sovereignty.preprocess.lookup_mx", side_effect=fake_lookup_mx),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "independent"

    async def test_no_mx_unknown(self):
        m = {"ags": "99999999", "name": "Zzz", "state": "Test", "website": ""}
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "unknown"

    async def test_gateway_detected_and_stored(self):
        m = {
            "ags": "08111000",
            "name": "Stuttgart",
            "state": "Baden-Württemberg",
            "website": "https://www.stuttgart.de",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["customer.seppmail.cloud"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "seppmail"

    async def test_spf_resolved_stored_when_different(self):
        m = {
            "ags": "01001000",
            "name": "Test",
            "state": "Test",
            "website": "https://www.test.de",
        }
        sem = __import__("asyncio").Semaphore(10)

        raw_spf = "v=spf1 include:custom.de -all"
        resolved_spf = "v=spf1 include:custom.de -all v=spf1 include:spf.protection.outlook.com -all"

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx01.hornetsecurity.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value=raw_spf,
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value=resolved_spf,
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "hornetsecurity"
        assert result["spf_resolved"] == resolved_spf

    async def test_autodiscover_stored_when_found(self):
        m = {
            "ags": "09162000",
            "name": "Fürth",
            "state": "Bayern",
            "website": "https://www.fuerth.de",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx01.hornetsecurity.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 ip4:1.2.3.4 -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 ip4:1.2.3.4 -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={"autodiscover_cname": "autodiscover.outlook.com"},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "hornetsecurity"
        assert result["autodiscover"] == {
            "autodiscover_cname": "autodiscover.outlook.com"
        }


# ── run() ────────────────────────────────────────────────────────────


class TestPreprocessRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "ags": {"value": "05315000"},
                                "itemLabel": {"value": "Köln"},
                                "website": {"value": "https://www.stadt-koeln.de"},
                                "stateLabel": {"value": "Nordrhein-Westfalen"},
                            },
                        ]
                    }
                },
            )
        )

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx.koeln.de"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            output = tmp_path / "data.json"
            await run(output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "05315000" in data["municipalities"]
