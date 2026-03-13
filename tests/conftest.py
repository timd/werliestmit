import json

import pytest


@pytest.fixture
def sample_municipality():
    return {
        "ags": "05315000",
        "name": "Köln",
        "state": "Nordrhein-Westfalen",
        "domain": "stadt-koeln.de",
        "mx": ["stadt-koeln-de.mail.protection.outlook.com"],
        "spf": "v=spf1 include:spf.protection.outlook.com -all",
        "provider": "microsoft",
    }


@pytest.fixture
def german_isp_municipality():
    return {
        "ags": "08111000",
        "name": "Stuttgart",
        "state": "Baden-Württemberg",
        "domain": "stuttgart.de",
        "mx": ["mail.stuttgart.de"],
        "spf": "v=spf1 ip4:1.2.3.4 ~all",
        "provider": "german-isp",
    }


@pytest.fixture
def unknown_municipality():
    return {
        "ags": "99999999",
        "name": "Testingen",
        "state": "Testland",
        "domain": "",
        "mx": [],
        "spf": "",
        "provider": "unknown",
    }


@pytest.fixture
def sample_data_json(tmp_path):
    data = {
        "generated": "2025-01-01T00:00:00Z",
        "total": 3,
        "counts": {"microsoft": 1, "german-isp": 1, "unknown": 1},
        "municipalities": {
            "05315000": {
                "ags": "05315000",
                "name": "Köln",
                "state": "Nordrhein-Westfalen",
                "domain": "stadt-koeln.de",
                "mx": ["stadt-koeln-de.mail.protection.outlook.com"],
                "spf": "v=spf1 include:spf.protection.outlook.com -all",
                "provider": "microsoft",
            },
            "08111000": {
                "ags": "08111000",
                "name": "Stuttgart",
                "state": "Baden-Württemberg",
                "domain": "stuttgart.de",
                "mx": ["mail.stuttgart.de"],
                "spf": "v=spf1 ip4:1.2.3.4 ~all",
                "provider": "german-isp",
            },
            "99999999": {
                "ags": "99999999",
                "name": "Testingen",
                "state": "Testland",
                "domain": "",
                "mx": [],
                "spf": "",
                "provider": "unknown",
            },
        },
    }
    path = tmp_path / "data.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path
