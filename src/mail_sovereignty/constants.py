import re

MICROSOFT_KEYWORDS = [
    "mail.protection.outlook.com",
    "outlook.com",
    "microsoft",
    "office365",
    "onmicrosoft",
    "spf.protection.outlook.com",
    "sharepointonline",
]
GOOGLE_KEYWORDS = [
    "google",
    "googlemail",
    "gmail",
    "_spf.google.com",
    "aspmx.l.google.com",
]
AWS_KEYWORDS = ["amazonaws", "amazonses", "awsdns"]

PROVIDER_KEYWORDS = {
    "microsoft": MICROSOFT_KEYWORDS,
    "google": GOOGLE_KEYWORDS,
    "aws": AWS_KEYWORDS,
}

FOREIGN_SENDER_KEYWORDS = {
    "mailchimp": ["mandrillapp.com", "mandrill", "mcsv.net"],
    "sendgrid": ["sendgrid"],
    "mailjet": ["mailjet"],
    "mailgun": ["mailgun"],
    "brevo": ["sendinblue", "brevo"],
    "mailchannels": ["mailchannels"],
    "smtp2go": ["smtp2go"],
    "nl2go": ["nl2go"],
    "hubspot": ["hubspotemail"],
    "knowbe4": ["knowbe4"],
    "hornetsecurity": ["hornetsecurity", "hornetdmarc"],
}

SPARQL_URL = "https://query.wikidata.org/sparql"
SPARQL_QUERY = """
SELECT ?item ?itemLabel ?ags ?website ?stateLabel ?districtLabel WHERE {
  ?item wdt:P31/wdt:P279* wd:Q262166 .   # instance of (or subclass of) Gemeinde in Germany
  ?item wdt:P439 ?ags .                   # German municipality key (AGS)
  FILTER NOT EXISTS {                      # exclude dissolved municipalities
    ?item wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {                      # exclude municipalities with ended P31 statement
    ?item p:P31 ?stmt .
    ?stmt ps:P31/wdt:P279* wd:Q262166 .
    ?stmt pq:P582 ?endTime .
    FILTER(?endTime <= NOW())
  }
  FILTER NOT EXISTS {                      # exclude municipalities replaced by a successor
    ?item wdt:P1366 ?successor .
  }
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL {
    ?item wdt:P131* ?state .
    ?state wdt:P31 wd:Q1221156 .           # Bundesland
  }
  OPTIONAL {
    ?item wdt:P131 ?district .
    ?district wdt:P31/wdt:P279* wd:Q106658 .  # Landkreis or kreisfreie Stadt
  }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "de,en" . }
}
ORDER BY xsd:integer(?ags)
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(r"linkTo_UnCryptMailto\(['\"]([^'\"]+)['\"]")
SKIP_DOMAINS = {
    "example.com",
    "example.de",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
}

SUBPAGES = [
    "/kontakt",
    "/kontakt/",
    "/impressum",
    "/impressum/",
    "/verwaltung",
    "/verwaltung/",
    "/rathaus",
    "/rathaus/",
    "/buergerservice",
    "/buergerservice/",
    "/gemeinde",
    "/gemeinde/",
]

GATEWAY_KEYWORDS = {
    "seppmail": ["seppmail.cloud", "seppmail.com"],
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com", "hornetsecurity.de"],
    "abxsec": ["abxsec.com"],
    "proofpoint": ["ppe-hosted.com"],
    "sophos": ["hydra.sophos.com"],
    "nospamproxy": ["nospamproxy.com"],
    "retarus": ["retarus.com", "retarus.de"],
    # German municipal IT consortia and state gateways
    "kvnbw": ["kvnbw.de"],
    "bayern-it": ["bayern.de"],
    "allinkl": ["kasserver.com"],
    "dataport": ["landsh.de"],
    "ispgateway": ["ispgateway.de"],
    "pzd-svn": ["pzd-svn.de"],
    "agenturserver": ["agenturserver.de"],
    "secure-mailgate": ["secure-mailgate.com"],
    "mvnet": ["mvnet.de"],
    "kdo": ["kdo.de"],
    "itebo": ["itebo.de"],
    "kommunale-it": ["kommunale.it"],
    "next-go": ["next-go.net"],
    "as-scan": ["as-scan.de"],
    "kis-asp": ["kis-asp.de"],
    "rechennetz": ["rechennetz.de"],
    "sis-schwerin": ["sis-schwerin.de"],
    "regioit": ["regioit-aachen.de"],
    "kdgoe": ["kdgoe.de"],
    "kdvz-frechen": ["kdvz-frechen.de"],
    "ennit": ["ennit.net"],
    "nol-is": ["nol-is.de"],
    "kraemer-it": ["kraemer-it.cloud"],
    "antispameurope": ["antispameurope.com"],
    "itk-rheinland": ["itk-rheinland.de"],
    "mimecast": ["mimecast.com"],
    "messagelabs": ["messagelabs.com"],
    "antispamcloud": ["antispamcloud.com"],
    "secumail": ["secumail.de"],
    "expurgate": ["expurgate.net"],
}

GERMAN_ISP_ASNS: dict[int, str] = {
    3320: "Deutsche Telekom",
    6724: "Strato",
    6830: "Vodafone Deutschland",
    8422: "NetCologne",
    8560: "1&1 / IONOS",
    24940: "Hetzner",
    51167: "Contabo",
    197540: "netcup",
}

CONCURRENCY = 10
CONCURRENCY_POSTPROCESS = 5
CONCURRENCY_SMTP = 3

SMTP_BANNER_KEYWORDS = {
    "microsoft": [
        "microsoft esmtp mail service",
        "outlook.com",
        "protection.outlook.com",
    ],
    "google": [
        "mx.google.com",
        "google esmtp",
    ],
    "aws": [
        "amazonaws",
        "amazonses",
    ],
}
