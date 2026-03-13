# WerLiestMit — Email Providers of German Municipalities


An interactive map showing where German municipalities host their email — whether with US hyperscalers (Microsoft, Google, AWS) or German providers or other solutions.

Adapted from [mxmap.ch](https://mxmap.ch)

**[View the live map](https://wer-liest-mit.de)**

[![Screenshot of Wer liest mit?](og-image.jpg)](https://wer-liest-mit.de)

## How it works

The data pipeline has three steps:

1. **Preprocess** -- Fetches all ~10,800 German municipalities from Wikidata, performs MX and SPF DNS lookups on their official domains, and classifies each municipality's email provider.
2. **Postprocess** -- Applies manual overrides for edge cases, retries DNS for unresolved domains, checks SMTP banners of independent MX hosts for hidden providers, then scrapes websites of still-unclassified municipalities for email addresses.
3. **Validate** -- Cross-validates MX and SPF records, assigns a confidence score (0-100) to each entry, and generates a validation report.
