# NIST CMVP API Reference

Static JSON API for NIST Cryptographic Module Validation Program data.

- **1,143** active validated modules
- **4,258** historical modules
- **239** modules in process
- **5,401** certificate detail records
- **1,776** certificates with algorithm summaries
- No auth required, unofficial project, GitHub Pages hosted.

Base URL: `https://hackidle.github.io/nist-cmvp-api/`

## Endpoints

### Index
`GET api/index.json` — API discovery endpoint with resource paths, documentation links, feature flags, and current counts.

### Metadata
`GET api/metadata.json` — Generation timestamp, source URLs, dataset counts, extraction metrics, and algorithm extraction status.

### JSON Schemas
`GET api/schemas/index.schema.json` — JSON Schema discovery document for the static API response files.

### Certificate Index
`GET api/certificates/index.json` — Compact discovery index for all 5,401 per-certificate detail files, including certificate numbers, datasets, paths, vendor/module names, statuses, standards, and algorithm counts.

### Search Indexes
`GET api/indexes/vendors.json`, `GET api/indexes/algorithms.json`, `GET api/indexes/statuses.json`, and `GET api/indexes/standards.json` — Split lookup files for common client-side search by vendor, algorithm, status, and standard.

### Data Quality
`GET api/data-quality.json` — Latest run quality report with misses, refreshed records, fallback usage, changed certificates, cache reuse checks, and the next scheduled weekly run.

### Changes
`GET api/changes.json` — Cumulative newest-first feed of added, removed, and summary-changed certificate numbers across recent weekly runs.

### Consumer Examples
`GET api/examples.json` — Copy-ready curl, Python, JavaScript, and agent-oriented query examples for vendor, module, algorithm, status, and standard lookups.

### Active Modules
`GET api/modules.json` — All 1,143 active validated modules.

Example response (truncated):

```json
{
  "metadata": {
    "generated_at": "2026-07-19T05:22:40.630488Z",
    "total_modules": 1143
  },
  "modules": [
    {
      "Certificate Number": "5424",
      "Vendor Name": "ZeroTier, Inc.",
      "Module Name": "ZeroTier, Inc. Cryptographic Module",
      "Module Type": "Software",
      "Validation Date": "07/17/2026",
      "standard": "FIPS 140-3",
      "status": "Active",
      "overall_level": 1,
      "sunset_date": "8/26/2029",
      "algorithms": [
        "AES",
        "CVL",
        "DES",
        "DRBG",
        "DSA",
        "ECDSA",
        "EDDSA",
        "HMAC",
        "KAS",
        "KDF",
        "KTS",
        "RSA",
        "SHA",
        "SSH",
        "TLS"
      ],
      "security_policy_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5424.pdf",
      "certificate_detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5424",
      "detail_available": true,
      "algorithm_extraction": {
        "schema_version": "1.0",
        "status": "parsed",
        "configured_source": "crawl4ai",
        "source": "crawl4ai",
        "source_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5424.pdf",
        "cached": false,
        "fallback_used": false,
        "cache_version": "2026-04-15-legacy-v1",
        "algorithm_count": 15,
        "detailed_algorithm_count": 206
      },
      "description": "The ZeroTier, Inc. Cryptographic Module is a software based cryptographic module that provides FIPS approved and allowed cryptographic services, including en...",
      "caveat": "No assurance of the minimum strength of generated SSPs (e.g., keys) and random strings. No assurance of minimum security of SSPs (e.g., keys, bit strings) th..."
    }
  ]
}
```

Each active module includes certificate identifiers, vendor/module names, validation metadata, direct Security Policy links, NIST detail URLs, detail availability flags, and algorithm extraction provenance when algorithms were evaluated.

### Historical Modules
`GET api/historical-modules.json` — All 4,258 expired or revoked modules for historical lookups.

### Modules In Process
`GET api/modules-in-process.json` — All 239 modules currently in the validation pipeline.

### Algorithms
`GET api/algorithms.json` — Algorithm usage summary across 1,776 certificates in the current build.

`algorithm_extraction` records the configured source, actual source, cache/fallback status, source URL, and extracted row counts for each evaluated certificate.

Example response (truncated):

```json
{
  "total_unique_algorithms": 19,
  "total_certificate_algorithm_pairs": 15996,
  "algorithms": {
    "AES": {
      "count": 1638,
      "certificates": [
        5388,
        5393,
        5385,
        5390,
        5387
      ]
    }
  }
}
```

### Certificate Details
`GET api/certificates/{certificate}.json` — Structured detail record for a specific certificate, including vendor/contact data, related files, validation history, and extracted algorithms when available.

Example response (truncated):

```json
{
  "metadata": {
    "generated_at": "2026-07-19T05:22:40.630488Z",
    "dataset": "active",
    "source": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5388"
  },
  "certificate": {
    "certificate_number": "5388",
    "dataset": "active",
    "vendor_name": "F5, Inc.",
    "module_name": "BIG-IP Tenant Cryptographic Module",
    "standard": "FIPS 140-3",
    "status": "Active",
    "module_type": "Firmware",
    "overall_level": 2,
    "validation_dates": [
      "7/9/2026"
    ],
    "sunset_date": "7/8/2031",
    "caveat": "When operated in approved mode. The tamper evident labels contained in F5-ADD-BIG-FIPS140 kit and installed as indicated in the Security Policy section 7. No...",
    "security_level_exceptions": [
      "Operational environment: N/A",
      "Non-invasive security: N/A",
      "Mitigation of other attacks: N/A"
    ],
    "vendor": {
      "name": "F5, Inc.",
      "website_url": "https://csrc.nist.gov/f5.com",
      "contact_email": "F5Certs@f5.com"
    },
    "related_files": [
      {
        "label": "Security Policy",
        "url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5388.pdf"
      }
    ],
    "validation_history": [
      {
        "date": "7/9/2026",
        "type": "Initial",
        "lab": "atsec information security corporation"
      }
    ],
    "algorithms": [
      "AES",
      "CVL",
      "DES",
      "DRBG",
      "DSA"
    ],
    "algorithm_extraction": {
      "schema_version": "1.0",
      "status": "cached",
      "configured_source": "crawl4ai",
      "source": "crawl4ai",
      "source_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5388.pdf",
      "cached": true,
      "fallback_used": false,
      "cache_version": "2026-04-15-legacy-v1",
      "algorithm_count": 14,
      "detailed_algorithm_count": 56
    }
  }
}
```

Current build contains 5,401 certificate detail records across active and historical datasets.

## Workflows

### Discover the API surface
```
GET api/index.json → endpoints, docs links, feature flags, counts
GET api/metadata.json → freshness, scrape provenance, and extraction metrics
GET api/data-quality.json → latest run misses, refreshes, fallbacks, changed certs, and next scheduled run
GET api/changes.json → recent added, removed, and summary-changed certificate numbers
```

### Find a module and pull the full certificate record
```
GET api/certificates/index.json → discover every certificate detail path and summary row
GET api/modules.json → locate the certificate number or vendor/module pair
GET api/certificates/5388.json → full detail record for that certificate
```

### Check validation status and history for a certificate
```
GET api/certificates/5388.json → status, sunset_date, validation_history, related_files
```

### Explore algorithm coverage
```
GET api/algorithms.json → counts and certificate lists per algorithm
GET api/indexes/algorithms.json → compact certificate refs keyed by algorithm
GET api/modules.json → filter module rows by algorithms[] entries and inspect algorithm_extraction
```

## Caveats

- **Unofficial:** This project mirrors public CMVP data and is not affiliated with NIST. Use `https://csrc.nist.gov/projects/cryptographic-module-validation-program` for authoritative source material.
- **Static JSON:** There is no server-side filtering. Use the split search indexes or download the relevant JSON file and filter client-side.
- **CORS:** GitHub Pages does not send permissive CORS headers. Browser JavaScript on another origin will usually need a proxy.
- **404s:** Invalid certificate numbers or file paths return GitHub Pages' default 404 page at `https://hackidle.github.io/nist-cmvp-api`.
- **Algorithms coverage:** `api/algorithms.json` summarizes 1,776 certificates that had algorithm data in this build. `api/metadata.json` reports extraction cache hits, refreshes, failures, misses, and fallback counts.