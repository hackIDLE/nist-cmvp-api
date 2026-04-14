# NIST CMVP API

Static JSON API for NIST Cryptographic Module Validation Program data. Auto-updates weekly via GitHub Actions.

## Features

- **Validated Modules**: Current FIPS 140-2/140-3 validated cryptographic modules
- **Historical Modules**: Expired/revoked modules for historical reference
- **Modules In Process**: Modules currently in validation
- **Algorithm Extraction**: Approved algorithms extracted locally from Security Policy PDFs
- **Security Policy Links**: Direct URLs to Security Policy PDF documents
- **Certificate Detail Records**: Per-certificate JSON with vendor, related files, validation history, and security level exceptions

## For Agents

- [`llms.txt`](https://hackidle.github.io/nist-cmvp-api/llms.txt) - discovery index
- [`llms-full.txt`](https://hackidle.github.io/nist-cmvp-api/llms-full.txt) - complete single-file reference
- [`api/docs.md`](https://hackidle.github.io/nist-cmvp-api/api/docs.md) - Markdown endpoint reference with examples
- [`openapi.json`](https://hackidle.github.io/nist-cmvp-api/openapi.json) - OpenAPI 3.0.3 schema

## Endpoints

Base URL: `https://hackidle.github.io/nist-cmvp-api/api/`

| Endpoint | Description |
|----------|-------------|
| `modules.json` | Validated cryptographic modules with algorithms and security policy URLs |
| `historical-modules.json` | Expired/revoked modules with security policy URLs |
| `modules-in-process.json` | Modules currently in validation |
| `algorithms.json` | Algorithm summary with usage statistics across all certificates |
| `metadata.json` | Dataset info (last update, counts, feature flags) |
| `index.json` | API index with all endpoints and feature information |
| `certificates/{certificate}.json` | Structured detail record for one CMVP certificate |

## Data Structure

### Module Entry

```json
{
  "Certificate Number": "5104",
  "Certificate Number_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5104",
  "Vendor Name": "Google, LLC",
  "Module Name": "BoringCrypto",
  "Module Type": "Software",
  "Validation Date": "12/09/2025",
  "security_policy_url": "https://csrc.nist.gov/CSRC/media/projects/.../140sp5104.pdf",
  "certificate_detail_url": "https://csrc.nist.gov/projects/.../certificate/5104",
  "standard": "FIPS 140-3",
  "status": "Active",
  "overall_level": 1,
  "sunset_date": "12/8/2030",
  "caveat": "When operated in approved mode. No assurance of the minimum strength of generated SSPs (e.g., keys)",
  "embodiment": "Multi-Chip Stand Alone",
  "description": "A software library that contains cryptographic functionality...",
  "lab": "DEKRA Cybersecurity Certification Laboratory",
  "algorithms": ["AES", "SHA-256", "RSA", "ECDSA", "HMAC", "DRBG"]
}
```

### Algorithm Summary (algorithms.json)

```json
{
  "total_unique_algorithms": 45,
  "total_certificate_algorithm_pairs": 8500,
  "algorithms": {
    "AES": {
      "count": 950,
      "certificates": [5104, 5103, ...]
    },
    "SHA-256": {
      "count": 920,
      "certificates": [...]
    }
  }
}
```

### Certificate Detail (`certificates/{certificate}.json`)

```json
{
  "metadata": {
    "generated_at": "2026-03-26T00:00:00.000000Z",
    "dataset": "active",
    "source": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5203"
  },
  "certificate": {
    "certificate_number": "5203",
    "dataset": "active",
    "generated_at": "2026-03-26T00:00:00.000000Z",
    "vendor_name": "OVH SAS",
    "module_name": "OVHCloud OKMS Provider based on the OpenSSL FIPS Provider",
    "standard": "FIPS 140-3",
    "status": "Active",
    "module_type": "Software",
    "overall_level": 1,
    "validation_dates": ["3/21/2026"],
    "sunset_date": "3/10/2030",
    "security_level_exceptions": ["Physical security: N/A"],
    "vendor": {
      "name": "OVH SAS",
      "website_url": "https://corporate.ovhcloud.com/en/",
      "address_lines": ["2 RUE KELLERMANN", "ROUBAIX 59100", "FRANCE"],
      "country": "FRANCE",
      "contact_name": "Data security team",
      "contact_email": "okms_fips@ovh.net",
      "contact_phone": "+33 3 20 82 73 32"
    },
    "related_files": [
      {
        "label": "Security Policy",
        "url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5203.pdf"
      }
    ],
    "validation_history": [
      {
        "date": "3/21/2026",
        "type": "Initial",
        "lab": "Lightship Security, Inc."
      }
    ],
    "algorithms": ["AES", "HMAC"]
  }
}
```

## Usage

```bash
# Get validated modules
curl https://hackidle.github.io/nist-cmvp-api/api/modules.json

# Filter by vendor (jq)
curl -s https://hackidle.github.io/nist-cmvp-api/api/modules.json | \
  jq '.modules[] | select(."Vendor Name" | contains("Microsoft"))'

# Find modules with specific algorithm
curl -s https://hackidle.github.io/nist-cmvp-api/api/modules.json | \
  jq '.modules[] | select(.algorithms != null and (.algorithms | contains(["AES-256"])))'

# Get all certificates using a specific algorithm
curl -s https://hackidle.github.io/nist-cmvp-api/api/algorithms.json | \
  jq '.algorithms["AES"].certificates'

# Get the full detail page payload for one certificate
curl -s https://hackidle.github.io/nist-cmvp-api/api/certificates/5203.json | jq '.certificate'

# Check last update
curl -s https://hackidle.github.io/nist-cmvp-api/api/metadata.json | jq '.generated_at'
```

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run full scraper (Firecrawl preferred when FIRECRAWL_API_KEY is set)
python scraper.py

# Force the local PDF fallback even when Firecrawl is available
unset FIRECRAWL_API_KEY && python scraper.py

# Run quick scraper (skip algorithm extraction entirely)
SKIP_ALGORITHMS=1 python scraper.py
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NIST_SEARCH_PATH` | `/all` | Override the search path for modules |
| `SKIP_ALGORITHMS` | `0` | Set to `1` to skip algorithm/detail extraction |
| `FIRECRAWL_API_KEY` | - | Prefer Firecrawl PDF-to-markdown extraction for algorithm parsing |
| `FIRECRAWL_TIMEOUT_MS` | `60000` | Firecrawl scrape timeout in milliseconds |
| `CMVP_DB_PATH` | - | Path to cmvp.db for algorithm import (fastest override) |
| `CERT_FETCH_CONCURRENCY` | `16` | Concurrent certificate detail page fetches |
| `PDF_FETCH_CONCURRENCY` | `32` | Concurrent Security Policy PDF or Firecrawl policy fetches |
| `FULL_REFRESH` | `0` | Set to `1` to bypass reuse of previously generated outputs |

GitHub Actions should provide `FIRECRAWL_API_KEY` as a repository secret. When that secret is absent, the scraper falls back to local Security Policy PDF parsing.

## CORS

GitHub Pages does not send permissive CORS headers. The API works well for CLIs, agents, and server-side consumers. Browser JavaScript on another origin usually needs a proxy.

## Source

Data scraped from [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program).

## Related Projects

- [NIST-CMVP-ReportGen](https://github.com/ethanolivertroy/NIST-CMVP-ReportGen) - Full-featured CMVP analysis CLI tool with PDF indexing and search
