#!/usr/bin/env python3
"""
NIST CMVP Data Scraper

This script scrapes the NIST Cryptographic Module Validation Program (CMVP)
validated modules database and saves the data as JSON files for a static API.

Features:
- Scrapes validated, historical, and in-process modules
- Extracts algorithm information from Security Policy PDFs
- Can import algorithm data from existing NIST-CMVP-ReportGen database
- Generates security policy PDF URLs

Environment Variables:
    NIST_SEARCH_PATH: Override the search path (default: /all)
                      Example: export NIST_SEARCH_PATH="/all"
    SKIP_ALGORITHMS: Set to "1" to skip algorithm extraction (faster scraping)
    ALGORITHM_SOURCE: Override algorithm extraction source: crawl4ai, security_policy_pdf, database, none
    CMVP_DB_PATH: Path to existing cmvp.db from NIST-CMVP-ReportGen project
                  If set, algorithm data will be imported from this database
    CERT_FETCH_CONCURRENCY: Concurrent certificate detail page fetches (default: 16)
    PDF_FETCH_CONCURRENCY: Concurrent Security Policy PDF fetches/parses (default: 32)
    CERT_PROCESS_TIMEOUT: Per-certificate processing timeout in seconds (default: 900)
    FULL_REFRESH: Set to "1" to bypass reuse of previously generated outputs
"""

import asyncio
import copy
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

import fitz
import httpx
import requests
from bs4 import BeautifulSoup

try:
    from crawl4ai.processors.pdf import PDFContentScrapingStrategy

    CRAWL4AI_AVAILABLE = True
except ImportError:
    PDFContentScrapingStrategy = None
    CRAWL4AI_AVAILABLE = False


BASE_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search"
CERTIFICATE_DETAIL_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate"
SECURITY_POLICY_BASE_URL = "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies"
MODULES_IN_PROCESS_URL = "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list"
# Allow override via environment variable for flexibility
SEARCH_PATH = os.getenv("NIST_SEARCH_PATH", "/all")
HISTORICAL_SEARCH_PARAMS = "?SearchMode=Advanced&CertificateStatus=Historical&ValidationYear=0"
USER_AGENT = "NIST-CMVP-Data-Scraper/1.0 (GitHub Project)"
SKIP_ALGORITHMS = os.getenv("SKIP_ALGORITHMS", "0") == "1"
CERT_FETCH_CONCURRENCY = max(1, int(os.getenv("CERT_FETCH_CONCURRENCY", "16")))
PDF_FETCH_CONCURRENCY = max(1, int(os.getenv("PDF_FETCH_CONCURRENCY", "32")))
CERT_PROCESS_TIMEOUT = max(1, int(os.getenv("CERT_PROCESS_TIMEOUT", "900")))
FULL_REFRESH = os.getenv("FULL_REFRESH", "0") == "1"

# Path to NIST-CMVP-ReportGen database (if available for importing algorithms)
CMVP_DB_PATH = os.getenv("CMVP_DB_PATH", "")
ALGORITHM_SOURCE_OVERRIDE = os.getenv("ALGORITHM_SOURCE", "").strip().lower().replace("-", "_")
PUBLIC_BASE_URL = "https://hackidle.github.io/nist-cmvp-api"
PUBLIC_API_BASE_URL = f"{PUBLIC_BASE_URL}/api"
REPO_URL = "https://github.com/hackIDLE/nist-cmvp-api"
OFFICIAL_CMVP_URL = "https://csrc.nist.gov/projects/cryptographic-module-validation-program"
DETAIL_DIR = Path("api/certificates")
CRAWL4AI_ALGORITHM_SOURCE = "crawl4ai"
SECURITY_POLICY_ALGORITHM_SOURCE = "security_policy_pdf"
ALGORITHM_CACHE_VERSION = "2026-04-15-legacy-v1"
ALGORITHM_EXTRACTION_SCHEMA_VERSION = "1.0"
CACHEABLE_ALGORITHM_SOURCES = {
    CRAWL4AI_ALGORITHM_SOURCE,
    SECURITY_POLICY_ALGORITHM_SOURCE,
    # Reuse the currently published algorithm payloads during extractor
    # migrations so unchanged certificates preserve existing API quality.
    "firecrawl",
}
CACHE_FINGERPRINT_FIELDS = [
    "Certificate Number",
    "Vendor Name",
    "Module Name",
    "Module Type",
    "Validation Date",
    "security_policy_url",
    "certificate_detail_url",
]
MODULE_DETAIL_FIELDS = [
    "module_name",
    "standard",
    "status",
    "sunset_date",
    "overall_level",
    "caveat",
    "module_type",
    "embodiment",
    "description",
    "software_versions",
    "hardware_versions",
    "firmware_versions",
    "security_policy_url",
    "algorithms",
    "algorithms_detailed",
]
DETAIL_SCHEMA_REQUIRED_FIELDS = (
    "standard",
    "status",
    "related_files",
    "validation_history",
    "vendor",
)
DETAIL_SCHEMA_MIGRATED_FIELDS = (
    "software_versions",
    "hardware_versions",
    "firmware_versions",
)

# Algorithm keywords to look for when parsing
# Order matters: more specific keywords should come before general ones (HMAC before SHA)
ALGORITHM_KEYWORDS = [
    'HMAC', 'AES', 'RSA', 'ECDSA', 'ECDH', 'DRBG',
    'KDF', 'DES', 'DSA', 'CVL', 'KAS', 'KTS', 'PBKDF',
    'SHS', 'SHA', 'TLS', 'SSH', 'EDDSA', 'ML-KEM', 'ML-DSA'
]

# Patterns to skip (UI elements, page chrome, not actual algorithms)
SKIP_PATTERNS = [
    'lock', 'padlock', 'https://', 'website', 'official',
    'share sensitive', 'connected to', '.gov', 'information only',
    'government', 'browser', 'cookies', 'description',
    'the module', 'provides', 'language api', 'functionality',
]

PDF_SECTION_LABELS = {
    "cipher",
    "key agreement",
    "key derivation",
    "key management",
    "key transport",
    "message authentication",
    "message digest",
    "random",
    "signature",
    "vendor-affirmed algorithms",
    "vendor affirmed algorithms",
}
LEGACY_SECTION_STOP_PATTERNS = (
    r"\n\s*Table\s+\d+\s+(?:FIPS\s+)?Non-Approved\s+Cryptographic\s+Functions\b",
    r"\n\s*Table\s+\d+\s+Non-Approved\s+Cryptographic\s+Algorithms\b",
    r"\n\s*\d+\.\d+(?:\.\d+)?\s+FIPS\s+Non-Approved\b",
    r"\n\s*\d+\.\d+(?:\.\d+)?\s+Non-Approved\b",
    r"\n\s*3\.5(?:\.1)?\s+(?:Allowed|Non-Approved)\s+Algorithms\b",
    r"\n\s*\d+\.\d+(?:\.\d+)?\s+Critical\s+Security\s+Parameters\b",
    r"\n\s*\d+\.\d+(?:\.\d+)?\s+General\s+Public\s+Keys\b",
    r"\n\s*2\.\s+[A-Za-z]",
    r"\n\s*3\.\s+[A-Za-z]",
    r"\n\s*4\.\d+\s+[A-Za-z]",
    r"\n\s*5\.\d+\s+[A-Za-z]",
    r"\n\s*6\.\d+\s+[A-Za-z]",
    r"\n\s*\d+\s+Cryptographic Key Management\b",
)
PDF_NOISE_PREFIXES = (
    "copyright",
    "this non-proprietary",
    "fips 140-3 security policy",
    "fips 140-3 non-proprietary security policy",
    "fips 140-2 non-proprietary security policy",
    "non-proprietary security policy",
    "page ",
    "table ",
    "algorithm cavp cert",
    "algorithm",
    "cavp cert",
    "properties",
    "reference",
    "approved algorithms",
    "vendor-affirmed algorithms",
    "vendor affirmed algorithms",
)
ALGORITHM_ENTRY_STOP_PHRASES = (
    "fips 140-3 non-proprietary security policy",
    "fips 140-2 non-proprietary security policy",
    "non-proprietary security policy",
    "this document can be reproduced",
    "this document may be reproduced",
    "non-approved, allowed algorithms",
    "non-approved allowed algorithms",
    "non-approved, not allowed algorithms",
    "non-approved not allowed algorithms",
    "non-approved, allowed algorithms with no security claimed",
    "non-approved allowed algorithms with no security claimed",
    "name use and function",
    "critical security parameters",
)
ALGORITHM_ENTRY_DROP_PARTS = {
    "algorithm",
    "cavp cert",
    "cert",
    "reference",
    "properties",
    "use",
    "function",
    "notes",
}
ALGORITHM_ENTRY_DROP_PATTERNS = (
    re.compile(r"^page\s+\d+(?:\s+of\s+\d+)?$", re.IGNORECASE),
    re.compile(r"^table\s+\d+\b", re.IGNORECASE),
    re.compile(r"^(?:copyright|\(c\)|©)\b", re.IGNORECASE),
    re.compile(r"^©\s+\d{4}\b", re.IGNORECASE),
)
PDF_CONTINUATION_PREFIXES = (
    "key length",
    "direction",
    "iv generation",
    "iv generation mode",
    "domain parameter generation methods",
    "domain parameter",
    "scheme",
    "kas role",
    "modulo",
    "key generation methods",
    "shared secret length",
    "derived key length",
    "mac salting methods",
    "hmac algorithm",
    "curve",
    "salt methods",
    "pred resistance",
    "returned bits length",
    "output block length",
    "entropy input length",
    "nonce length",
    "additional input length",
    "personalization string length",
    "security strength",
    "sp800-",
    "sp 800-",
    "rev. ",
    "kas1 -",
    "kas2 -",
    "dhephem -",
)
LEGACY_TABLE_HEADER_LINES = {
    "algorithm",
    "algorithm / modes",
    "algorithm type",
    "label",
    "standard",
    "modes / key sizes",
    "cert",
    "usage",
    "notes",
    "description",
    "service",
    "services",
    "cryptographic services",
    "security function",
    "security functions",
    "reference",
    "properties",
    "mode / key sizes",
}
ALGORITHM_CATEGORY_PATTERNS = [
    ("ML-KEM", re.compile(r"\bML-KEM\b", re.IGNORECASE)),
    ("ML-DSA", re.compile(r"\bML-DSA\b", re.IGNORECASE)),
    ("EDDSA", re.compile(r"\bEDDSA\b", re.IGNORECASE)),
    ("HMAC", re.compile(r"\bHMAC\b", re.IGNORECASE)),
    ("AES", re.compile(r"\bAES\b", re.IGNORECASE)),
    ("RSA", re.compile(r"\bRSA\b", re.IGNORECASE)),
    ("ECDSA", re.compile(r"\bECDSA\b", re.IGNORECASE)),
    ("ECDH", re.compile(r"\bECDH\b", re.IGNORECASE)),
    ("DRBG", re.compile(r"(?:\b|_)DRBG\b", re.IGNORECASE)),
    ("KDF", re.compile(r"\b(KDF|KDA|KBKDF|HKDF|PBKDF)\b", re.IGNORECASE)),
    ("KAS", re.compile(r"\bKAS\b", re.IGNORECASE)),
    ("KTS", re.compile(r"\bKTS\b", re.IGNORECASE)),
    ("DSA", re.compile(r"\bDSA\b", re.IGNORECASE)),
    ("DES", re.compile(r"\bTDES\b|\bDES\b", re.IGNORECASE)),
    ("SHA", re.compile(r"\bSHA(?:\d|-)?", re.IGNORECASE)),
    ("SHS", re.compile(r"\bSHS\b", re.IGNORECASE)),
    ("TLS", re.compile(r"\bTLS\b", re.IGNORECASE)),
    ("SSH", re.compile(r"\bSSH\b", re.IGNORECASE)),
    ("CVL", re.compile(r"\bCVL\b", re.IGNORECASE)),
]

PROCESSING_STAT_KEYS = (
    "html_reused",
    "html_refreshed",
    "html_failed",
    "pdf_reused",
    "pdf_refreshed",
    "pdf_failed",
    "pdf_cache_hits",
    "algorithm_misses",
    "algorithm_cache_hits",
    "algorithm_successes",
    "algorithm_fallbacks",
    "algorithm_source_crawl4ai",
    "algorithm_source_security_policy_pdf",
    "algorithm_source_database",
    "algorithm_source_none",
    "certificate_timeouts",
)


@dataclass
class AlgorithmExtractionResult:
    """Result of attempting to extract algorithms for one Security Policy."""

    detailed: List[str]
    categories: List[str]
    parsed: bool
    source: str
    source_url: Optional[str] = None
    fallback_used: bool = False
    pdf_cache_hits: int = 0
    attempts: List[Dict[str, str]] = field(default_factory=list)


def fetch_page(url: str, timeout: int = 30, retries: int = 3) -> Optional[str]:
    """
    Fetch a web page and return its HTML content.

    Retries with exponential backoff on transient failures (5xx, 429, timeouts).

    Args:
        url: The URL to fetch
        timeout: Request timeout in seconds
        retries: Number of retry attempts

    Returns:
        HTML content as string, or None if all attempts fail
    """
    headers = {"User-Agent": USER_AGENT}
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                print(f"Rate limited on {url}, waiting {retry_after}s...", file=sys.stderr)
                time.sleep(retry_after)
                continue
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            if attempt < retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"Attempt {attempt + 1}/{retries} failed for {url}: {e}. Retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
            else:
                print(f"Error fetching {url} after {retries} attempts: {e}", file=sys.stderr)
    return None


def get_security_policy_url(cert_number: int) -> str:
    """
    Get the URL for a certificate's Security Policy PDF.

    Args:
        cert_number: The certificate number

    Returns:
        URL to the security policy PDF
    """
    return f"{SECURITY_POLICY_BASE_URL}/140sp{cert_number}.pdf"


def get_certificate_detail_url(cert_number: int) -> str:
    """
    Get the URL for a certificate's detail page.

    Args:
        cert_number: The certificate number

    Returns:
        URL to the certificate detail page
    """
    return f"{CERTIFICATE_DETAIL_URL}/{cert_number}"


def normalize_whitespace(value: str) -> str:
    """Collapse repeated whitespace into single spaces."""
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def normalize_string_list(values: Optional[List[str]]) -> List[str]:
    """Normalize, deduplicate, and preserve order for a list of strings."""
    normalized: List[str] = []
    seen: Set[str] = set()
    for value in values or []:
        if value is None:
            continue
        text = normalize_whitespace(str(value))
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


def new_processing_stats() -> Dict[str, int]:
    """Return zeroed scrape/extraction counters for one dataset or certificate."""
    return {key: 0 for key in PROCESSING_STAT_KEYS}


def add_processing_stats(target: Dict[str, int], increment: Dict[str, int]) -> None:
    """Add processing counters from one stats dictionary into another."""
    for key in PROCESSING_STAT_KEYS:
        target[key] = target.get(key, 0) + increment.get(key, 0)


def combine_processing_stats(*stats_dicts: Dict[str, int]) -> Dict[str, int]:
    """Combine multiple processing stats dictionaries into one."""
    combined = new_processing_stats()
    for stats in stats_dicts:
        add_processing_stats(combined, stats)
    return combined


def build_extraction_metrics(active_stats: Dict[str, int], historical_stats: Dict[str, int]) -> Dict[str, object]:
    """Build metadata-safe scrape and algorithm extraction metrics."""
    return {
        "active": dict(active_stats),
        "historical": dict(historical_stats),
        "combined": combine_processing_stats(active_stats, historical_stats),
        "concurrency": {
            "certificate_fetch": CERT_FETCH_CONCURRENCY,
            "security_policy_fetch": PDF_FETCH_CONCURRENCY,
            "certificate_process_timeout_seconds": CERT_PROCESS_TIMEOUT,
        },
    }


def build_algorithm_extraction_provenance(
    configured_source: str,
    status: str,
    source: str,
    source_url: Optional[str],
    categories: Optional[List[str]],
    detailed: Optional[List[str]],
    cached: bool = False,
    fallback_used: bool = False,
    attempts: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, object]:
    """Build the per-certificate provenance object for algorithm extraction."""
    cleaned_categories = normalize_string_list(categories or [])
    cleaned_details = sanitize_algorithm_details(detailed or [])
    provenance = {
        "schema_version": ALGORITHM_EXTRACTION_SCHEMA_VERSION,
        "status": status,
        "configured_source": configured_source,
        "source": source,
        "source_url": source_url,
        "cached": cached,
        "fallback_used": fallback_used,
        "cache_version": ALGORITHM_CACHE_VERSION,
        "algorithm_count": len(cleaned_categories),
        "detailed_algorithm_count": len(cleaned_details),
    }
    if attempts is not None:
        provenance["attempts"] = attempts
    return provenance


def apply_algorithm_extraction_provenance(
    record: Optional[Dict],
    provenance: Dict[str, object],
    include_attempts: bool = False,
) -> None:
    """Attach algorithm extraction provenance to a module or detail payload."""
    if record is None:
        return
    payload = dict(provenance)
    if not include_attempts:
        payload.pop("attempts", None)
    record["algorithm_extraction"] = payload


def cached_algorithm_extraction_source(
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
    previous_metadata: Dict,
) -> Tuple[str, Optional[str]]:
    """Return the best available extraction source metadata for cached algorithms."""
    previous_extraction = (
        (previous_detail or {}).get("algorithm_extraction")
        or (previous_module or {}).get("algorithm_extraction")
        or {}
    )
    source = previous_extraction.get("source") or previous_metadata.get("algorithm_source") or "cache"
    source_url = previous_extraction.get("source_url")
    return str(source), source_url if isinstance(source_url, str) else None


def parse_certificate_number(record: Optional[Dict]) -> Optional[int]:
    """Extract an integer certificate number from a module row or detail payload."""
    if not record:
        return None

    for key in ("Certificate Number", "certificate_number"):
        value = str(record.get(key, "")).strip()
        if value.isdigit():
            return int(value)
    return None


def strip_algorithm_fields(record: Dict) -> None:
    """Remove algorithm fields from a module row or detail payload in place."""
    record.pop("algorithms", None)
    record.pop("algorithms_detailed", None)


def sanitize_algorithm_details(detailed: Optional[List[str]]) -> List[str]:
    """Normalize and clean detailed algorithm rows from fresh or cached extraction."""
    cleaned_entries: List[str] = []
    for entry in detailed or []:
        cleaned = format_algorithm_entry([str(entry)])
        if not cleaned:
            continue
        if not any(pattern.search(cleaned) for _, pattern in ALGORITHM_CATEGORY_PATTERNS):
            continue
        cleaned_entries.append(cleaned)
    return normalize_string_list(cleaned_entries)


def apply_algorithm_fields(record: Dict, categories: List[str], detailed: List[str]) -> None:
    """Apply normalized algorithm fields to a module row or detail payload."""
    strip_algorithm_fields(record)
    if categories:
        record["algorithms"] = normalize_string_list(categories)
    cleaned_details = sanitize_algorithm_details(detailed)
    if cleaned_details:
        record["algorithms_detailed"] = cleaned_details


def make_absolute_url(url: str) -> str:
    """Resolve a CSRC-relative URL to an absolute URL."""
    return urljoin("https://csrc.nist.gov", url)


def decode_cloudflare_email(encoded: str) -> str:
    """
    Decode Cloudflare's data-cfemail obfuscation.

    Args:
        encoded: Hex-encoded cfemail payload

    Returns:
        Decoded email, or empty string on failure
    """
    if not encoded:
        return ""

    try:
        key = int(encoded[:2], 16)
        chars = [
            chr(int(encoded[i:i + 2], 16) ^ key)
            for i in range(2, len(encoded), 2)
        ]
        return "".join(chars)
    except Exception:
        return ""


def find_panel_by_title(soup: BeautifulSoup, title: str):
    """Find a CMVP page panel by its heading text."""
    heading = soup.find(
        lambda tag: tag.name in {"h2", "h3", "h4"}
        and normalize_whitespace(tag.get_text(" ", strip=True)) == title
    )
    return heading.find_parent("div", class_="panel") if heading else None


def parse_detail_rows(panel_body) -> Dict[str, object]:
    """
    Parse the label/value rows in the NIST certificate Details panel.

    Args:
        panel_body: BeautifulSoup node for the Details panel body

    Returns:
        Dictionary of parsed certificate detail fields
    """
    detail_fields: Dict[str, object] = {}
    field_map = {
        "Module Name": "module_name",
        "Standard": "standard",
        "Status": "status",
        "Sunset Date": "sunset_date",
        "Overall Level": "overall_level",
        "Caveat": "caveat",
        "Module Type": "module_type",
        "Embodiment": "embodiment",
        "Description": "description",
        "Software Versions": "software_versions",
        "Hardware Versions": "hardware_versions",
        "Firmware Versions": "firmware_versions",
    }

    for row in panel_body.find_all("div", class_="row"):
        columns = row.find_all("div", recursive=False)
        if len(columns) < 2:
            continue

        label = normalize_whitespace(columns[0].get_text(" ", strip=True)).rstrip(":")
        value_cell = columns[1]

        if label == "Security Level Exceptions":
            exceptions = [
                normalize_whitespace(item.get_text(" ", strip=True))
                for item in value_cell.find_all("li")
                if normalize_whitespace(item.get_text(" ", strip=True))
            ]
            if exceptions:
                detail_fields["security_level_exceptions"] = exceptions
            continue

        field_name = field_map.get(label)
        if not field_name:
            continue

        value = normalize_whitespace(value_cell.get_text(" ", strip=True))
        if not value:
            continue

        if field_name == "overall_level":
            match = re.search(r"\d+", value)
            detail_fields[field_name] = int(match.group()) if match else value
        else:
            detail_fields[field_name] = value

    return detail_fields


def parse_vendor_panel(panel) -> Dict[str, object]:
    """
    Parse the vendor/contact block from a certificate page.

    Args:
        panel: BeautifulSoup node for the Vendor panel

    Returns:
        Structured vendor information
    """
    body = panel.find("div", class_="panel-body") if panel else None
    if not body:
        return {}

    vendor_name = ""
    vendor_website_url = None
    vendor_link = body.find("a", href=True)
    if vendor_link:
        vendor_name = normalize_whitespace(vendor_link.get_text(" ", strip=True))
        vendor_website_url = make_absolute_url(vendor_link["href"])

    address_lines = [
        normalize_whitespace(span.get_text(" ", strip=True))
        for span in body.find_all("span", class_="indent", recursive=False)
        if normalize_whitespace(span.get_text(" ", strip=True))
    ]

    contact_name = ""
    contact_email = None
    contact_phone = None
    contact_block = body.find("div", style=lambda value: value and "font-size" in value)
    if contact_block:
        contact_span = contact_block.find("span")
        if contact_span:
            pieces = []
            for child in contact_span.contents:
                if getattr(child, "name", None) == "br":
                    break
                if isinstance(child, str):
                    pieces.append(child)
                else:
                    pieces.append(child.get_text(" ", strip=True))
            contact_name = normalize_whitespace(" ".join(pieces))

        email_link = contact_block.find("a", href=True)
        if email_link:
            if email_link.get("data-cfemail"):
                contact_email = decode_cloudflare_email(email_link["data-cfemail"])
            elif email_link["href"].startswith("mailto:"):
                contact_email = email_link["href"].split(":", 1)[1].strip()
            else:
                email_text = normalize_whitespace(email_link.get_text(" ", strip=True))
                if email_text and "[email" not in email_text.lower():
                    contact_email = email_text

        lines = [
            normalize_whitespace(line)
            for line in contact_block.get_text("\n", strip=True).splitlines()
            if normalize_whitespace(line)
        ]
        for line in lines:
            if line.lower().startswith("phone:"):
                contact_phone = line.split(":", 1)[1].strip()
                break

    return {
        "name": vendor_name,
        "website_url": vendor_website_url,
        "address_lines": address_lines,
        "country": address_lines[-1] if address_lines else None,
        "contact_name": contact_name or None,
        "contact_email": contact_email or None,
        "contact_phone": contact_phone or None,
    }


def parse_related_files_panel(panel) -> List[Dict[str, str]]:
    """
    Parse the Related Files panel.

    Args:
        panel: BeautifulSoup node for the Related Files panel

    Returns:
        List of labeled file links
    """
    body = panel.find("div", class_="panel-body") if panel else None
    if not body:
        return []

    files = []
    seen = set()
    for link in body.find_all("a", href=True):
        label = normalize_whitespace(link.get_text(" ", strip=True))
        url = make_absolute_url(link["href"])
        if not label or not url or url in seen:
            continue
        seen.add(url)
        files.append({
            "label": label,
            "url": url,
        })

    return files


def parse_validation_history_panel(panel) -> List[Dict[str, str]]:
    """
    Parse the Validation History table.

    Args:
        panel: BeautifulSoup node for the Validation History panel

    Returns:
        Ordered list of validation history rows
    """
    body = panel.find("div", class_="panel-body") if panel else None
    if not body:
        return []

    table = body.find("table")
    if not table:
        return []

    history = []
    tbody = table.find("tbody")
    rows = tbody.find_all("tr") if tbody else table.find_all("tr")
    for row in rows:
        cells = row.find_all("td")
        if len(cells) < 3:
            continue
        date = normalize_whitespace(cells[0].get_text(" ", strip=True))
        event_type = normalize_whitespace(cells[1].get_text(" ", strip=True))
        lab = normalize_whitespace(cells[2].get_text(" ", strip=True))
        if not date and not event_type and not lab:
            continue
        history.append({
            "date": date,
            "type": event_type,
            "lab": lab,
        })

    return history


def parse_certificate_detail_page(
    html: str,
    cert_number: int,
    summary_module: Optional[Dict] = None,
    dataset: str = "active",
    generated_at: Optional[str] = None,
) -> Dict:
    """
    Parse a NIST CMVP certificate page into a structured detail record.

    Args:
        html: Raw HTML for the certificate page
        cert_number: Certificate number
        summary_module: Optional summary module row for fallback values
        dataset: Source dataset label (active or historical)
        generated_at: Upstream generation timestamp

    Returns:
        Structured certificate detail record
    """
    summary_module = summary_module or {}
    soup = BeautifulSoup(html, "lxml")

    details_panel = find_panel_by_title(soup, "Details")
    vendor_panel = find_panel_by_title(soup, "Vendor")
    related_files_panel = find_panel_by_title(soup, "Related Files")
    validation_history_panel = find_panel_by_title(soup, "Validation History")

    detail_fields = parse_detail_rows(details_panel.find("div", class_="panel-body")) if details_panel else {}
    vendor = parse_vendor_panel(vendor_panel)
    related_files = parse_related_files_panel(related_files_panel)
    validation_history = parse_validation_history_panel(validation_history_panel)
    validation_dates = []
    seen_dates = set()
    for entry in validation_history:
        date = entry.get("date", "")
        if date and date not in seen_dates:
            seen_dates.add(date)
            validation_dates.append(date)

    security_policy = next(
        (item["url"] for item in related_files if item["label"].lower() == "security policy"),
        None,
    )
    security_policy_url = security_policy or summary_module.get("security_policy_url")

    module_name = detail_fields.get("module_name") or summary_module.get("Module Name")
    standard = detail_fields.get("standard") or summary_module.get("standard") or summary_module.get("Standard")
    status = detail_fields.get("status") or summary_module.get("status") or summary_module.get("Status")
    module_type = detail_fields.get("module_type") or summary_module.get("module_type") or summary_module.get("Module Type")
    vendor_name = vendor.get("name") or summary_module.get("Vendor Name")
    algorithms = summary_module.get("algorithms") or []

    return {
        "certificate_number": str(cert_number),
        "dataset": dataset,
        "generated_at": generated_at,
        "nist_page_url": get_certificate_detail_url(cert_number),
        "certificate_detail_url": get_certificate_detail_url(cert_number),
        "security_policy_url": security_policy_url,
        "vendor_name": vendor_name,
        "module_name": module_name,
        "standard": standard,
        "status": status,
        "module_type": module_type,
        "embodiment": detail_fields.get("embodiment") or summary_module.get("embodiment"),
        "overall_level": detail_fields.get("overall_level") or summary_module.get("overall_level"),
        "validation_date": ", ".join(validation_dates) if validation_dates else summary_module.get("Validation Date"),
        "validation_dates": validation_dates,
        "sunset_date": detail_fields.get("sunset_date") or summary_module.get("sunset_date"),
        "caveat": detail_fields.get("caveat") or summary_module.get("caveat"),
        "description": detail_fields.get("description") or summary_module.get("description"),
        "software_versions": detail_fields.get("software_versions"),
        "hardware_versions": detail_fields.get("hardware_versions"),
        "firmware_versions": detail_fields.get("firmware_versions"),
        "security_level_exceptions": detail_fields.get("security_level_exceptions", []),
        "related_files": related_files,
        "validation_history": validation_history,
        "vendor": vendor,
        "algorithms": algorithms,
    }


def load_json_file(filepath: Path) -> Optional[Dict]:
    """Load a JSON file when it exists and return None on parse failure."""
    if not filepath.exists():
        return None

    try:
        with filepath.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        print(f"Warning: Failed to load cached JSON from {filepath}: {exc}", file=sys.stderr)
        return None


def load_previous_outputs(output_dir: Path = Path("api")) -> Dict[str, object]:
    """Load previously generated module rows, certificate details, and metadata."""
    active_data = load_json_file(output_dir / "modules.json") or {}
    historical_data = load_json_file(output_dir / "historical-modules.json") or {}
    metadata = load_json_file(output_dir / "metadata.json") or {}
    detail_payloads: Dict[int, Dict] = {}

    if DETAIL_DIR.exists():
        for filepath in DETAIL_DIR.glob("*.json"):
            payload = load_json_file(filepath) or {}
            certificate = payload.get("certificate")
            cert_num = parse_certificate_number(certificate)
            if cert_num is not None and isinstance(certificate, dict):
                detail_payloads[cert_num] = certificate

    def build_module_map(records: List[Dict]) -> Dict[int, Dict]:
        mapping: Dict[int, Dict] = {}
        for record in records or []:
            cert_num = parse_certificate_number(record)
            if cert_num is not None:
                mapping[cert_num] = record
        return mapping

    return {
        "metadata": metadata,
        "modules": {
            "active": build_module_map(active_data.get("modules", [])),
            "historical": build_module_map(historical_data.get("modules", [])),
        },
        "details": detail_payloads,
    }


def build_certificate_fingerprint(module: Dict, dataset: str) -> str:
    """Build a stable fingerprint for a certificate row based on summary fields."""
    payload = {"dataset": dataset}
    for key in CACHE_FINGERPRINT_FIELDS:
        payload[key] = module.get(key)
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def should_reuse_certificate_detail(
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
    previous_fingerprint: Optional[str],
    current_fingerprint: str,
) -> bool:
    """Return whether cached certificate detail HTML parsing can be skipped."""
    if FULL_REFRESH or previous_module is None or previous_detail is None:
        return False
    if previous_fingerprint != current_fingerprint:
        return False
    return all(field in previous_detail for field in DETAIL_SCHEMA_REQUIRED_FIELDS)


def prepare_reused_detail_payload(
    previous_detail: Dict,
    module: Dict,
    cert_number: int,
    dataset: str,
    generated_at: str,
) -> Dict:
    """Copy a cached certificate detail payload into the current run context."""
    payload = copy.deepcopy(previous_detail)
    payload["certificate_number"] = str(cert_number)
    payload["dataset"] = dataset
    payload["generated_at"] = generated_at
    payload["nist_page_url"] = payload.get("nist_page_url") or get_certificate_detail_url(cert_number)
    payload["certificate_detail_url"] = module.get("certificate_detail_url") or payload.get("certificate_detail_url") or get_certificate_detail_url(cert_number)
    payload["security_policy_url"] = payload.get("security_policy_url") or module.get("security_policy_url")
    payload["vendor_name"] = payload.get("vendor_name") or module.get("Vendor Name")
    payload["module_name"] = payload.get("module_name") or module.get("Module Name")
    for field in DETAIL_SCHEMA_MIGRATED_FIELDS:
        payload.setdefault(field, None)
    return payload


def cached_algorithm_fields(previous_module: Optional[Dict], previous_detail: Optional[Dict]) -> Tuple[List[str], List[str]]:
    """Return cached algorithm categories and detailed entries, if present."""
    categories = normalize_string_list(
        (previous_detail or {}).get("algorithms")
        or (previous_module or {}).get("algorithms")
        or []
    )
    detailed = normalize_string_list(
        (previous_detail or {}).get("algorithms_detailed")
        or (previous_module or {}).get("algorithms_detailed")
        or []
    )
    return categories, sanitize_algorithm_details(detailed)


def should_reuse_cached_algorithms(
    algorithm_source: str,
    fingerprint_matches: bool,
    previous_metadata: Dict,
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
) -> bool:
    """
    Decide whether a cached algorithm payload is safe to reuse.

    Parser upgrades should trigger retries for previously empty algorithm
    payloads, while still allowing non-empty cached results to be reused so we
    do not force a full backfill on every extraction tweak.
    """
    if algorithm_source not in CACHEABLE_ALGORITHM_SOURCES:
        return False
    if not fingerprint_matches:
        return False
    if previous_metadata.get("algorithm_source") not in CACHEABLE_ALGORITHM_SOURCES:
        return False

    previous_cache_version = previous_metadata.get("algorithm_cache_version")
    if previous_cache_version == ALGORITHM_CACHE_VERSION:
        return True

    categories, detailed = cached_algorithm_fields(previous_module, previous_detail)
    return bool(categories or detailed)


def prune_orphan_certificate_details(current_cert_numbers: Set[int], detail_dir: Path = DETAIL_DIR) -> int:
    """
    Remove stale certificate detail files for certs no longer present upstream.

    Keep files for any cert still present in the active or historical datasets,
    even if the current run failed to rebuild that cert's detail payload.
    """
    if not detail_dir.exists():
        return 0

    removed = 0
    for filepath in detail_dir.glob("*.json"):
        if not filepath.stem.isdigit():
            continue
        if int(filepath.stem) in current_cert_numbers:
            continue
        filepath.unlink()
        removed += 1

    return removed


def extract_policy_text_from_pdf_bytes(pdf_bytes: bytes) -> str:
    """Extract raw text from a Security Policy PDF using PyMuPDF."""
    document = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        return "\n".join(page.get_text("text") for page in document)
    finally:
        document.close()


def extract_algorithm_section(policy_text: str) -> str:
    """Extract the full 2.5 Algorithms section from policy text."""
    if not policy_text:
        return ""

    matches = list(re.finditer(r"2\.5\s+Algorithms\b", policy_text, flags=re.IGNORECASE))
    if not matches:
        return ""

    start = matches[-1].start()
    tail = policy_text[start:]
    end_match = re.search(
        r"\n2\.(?:6|7)\s+[A-Za-z]|\n3\s+Cryptographic Module Interfaces\b",
        tail,
        flags=re.IGNORECASE,
    )
    end = start + end_match.start() if end_match else len(policy_text)
    return policy_text[start:end]


def extract_legacy_algorithm_section(policy_text: str) -> str:
    """Extract approved-algorithm sections from older FIPS 140-2 style policies."""
    if not policy_text:
        return ""

    start_patterns = [
        r"\d+\.\d+(?:\.\d+)?\s+FIPS\s+Approved\s+Algorithms\b",
        r"\d+\.\d+(?:\.\d+)?\s+FIPS-Approved\s+Algorithms\b",
        r"\d+\.\d+(?:\.\d+)?\s+Approved\s+and\s+Non-Approved\s+Algorithms\b",
        r"\d+\.\d+(?:\.\d+)?\s+Approved\s+Cryptographic\s+Algorithms\b",
        r"Table\s+\d+\s+[–-]\s+FIPS-Approved\s+Algorithm\s+Implementations\b",
        r"Table\s+\d+\s+[–-]\s+FIPS-Approved\s+Algorithm\s+Certificates\b",
        r"FIPS-Approved\s+Algorithm\s+Implementations\b",
        r"FIPS-Approved\s+Algorithm\s+Certificates\b",
        r"Table\s+\d+\s+(?:FIPS\s+)?Approved\s+Cryptographic\s+Functions\b",
        r"Table\s+\d+\s+Approved\s+Cryptographic\s+Algorithms\b",
        r"Table\s+\d+\s+Approved\s+Algorithms\b",
        r"Table\s+\d+\s+below\s+lists\s+the\s+FIPS\s+Approved\s+cryptographic\s+algorithms\b",
        r"3\.4\s+Algorithms\b",
        r"Approved\s+Cryptographic\s+Functions\b",
    ]

    matches = []
    for pattern in start_patterns:
        pattern_matches = list(re.finditer(pattern, policy_text, flags=re.IGNORECASE))
        if pattern_matches:
            matches.extend(pattern_matches[-2:])

    if not matches:
        return ""

    stop_pattern = "|".join(LEGACY_SECTION_STOP_PATTERNS)
    best_section = ""
    best_score = (-1, -1)

    for match in matches:
        start = match.start()
        tail = policy_text[start:]
        end_match = re.search(stop_pattern, tail, flags=re.IGNORECASE)
        end = start + end_match.start() if end_match else len(policy_text)
        section = policy_text[start:end]
        if not section:
            continue

        category_hits = sum(1 for _, pattern in ALGORITHM_CATEGORY_PATTERNS if pattern.search(section))
        dot_leader_lines = section.count("....")
        score = (
            category_hits,
            -dot_leader_lines,
            start,
            len(section),
        )
        if score > best_score:
            best_score = score
            best_section = section

    return best_section


def is_policy_noise_line(line: str) -> bool:
    """Return True when a normalized policy line is boilerplate instead of algorithm data."""
    lower = line.lower()
    if not lower:
        return True
    if lower in ALGORITHM_ENTRY_DROP_PARTS:
        return True
    if any(pattern.search(line) for pattern in ALGORITHM_ENTRY_DROP_PATTERNS):
        return True
    if lower.endswith("cryptographic module"):
        return True
    if lower in PDF_SECTION_LABELS:
        return True
    return any(lower.startswith(prefix) for prefix in PDF_NOISE_PREFIXES)


def is_algorithm_entry_start(line: str) -> bool:
    """Identify the start of an algorithm row within extracted PDF text."""
    if not line or is_policy_noise_line(line):
        return False

    lower = line.lower()
    if any(lower.startswith(prefix) for prefix in PDF_CONTINUATION_PREFIXES):
        return False

    if re.match(r"^(2\.5|2\.6|2\.7|3\b)", line):
        return False

    return any(pattern.search(line) for _, pattern in ALGORITHM_CATEGORY_PATTERNS)


def trim_algorithm_entry_part(part: str) -> str:
    """Remove PDF table/page boilerplate that leaks into algorithm rows."""
    text = normalize_whitespace(part)
    if not text:
        return ""

    lower = text.lower()
    for phrase in ALGORITHM_ENTRY_STOP_PHRASES:
        index = lower.find(phrase)
        if index >= 0:
            text = text[:index]
            lower = text.lower()
            break

    text = normalize_whitespace(text).strip(" |;:,")
    if not text:
        return ""

    lower = text.lower()
    if lower in ALGORITHM_ENTRY_DROP_PARTS:
        return ""
    if any(pattern.search(text) for pattern in ALGORITHM_ENTRY_DROP_PATTERNS):
        return ""
    return text


def format_algorithm_entry(parts: List[str]) -> str:
    """Collapse a parsed algorithm row into a single line for JSON output."""
    cleaned_parts: List[str] = []
    for part in parts:
        cleaned = trim_algorithm_entry_part(part)
        if not cleaned:
            continue
        cleaned_parts.append(cleaned)
    return normalize_whitespace(" | ".join(cleaned_parts))


def categorize_algorithm_entry(entry: str) -> List[str]:
    """Map a detailed algorithm row to one or more simplified categories."""
    categories = [
        name
        for name, pattern in ALGORITHM_CATEGORY_PATTERNS
        if pattern.search(entry)
    ]
    normalized = normalize_string_list(categories)
    if "HMAC" in normalized and "SHA" in normalized:
        normalized = [value for value in normalized if value != "SHA"]
    if any(value in normalized for value in {"ECDSA", "EDDSA", "ML-DSA"}) and "DSA" in normalized:
        normalized = [value for value in normalized if value != "DSA"]
    return normalized


def parse_categories_from_legacy_section(section: str) -> List[str]:
    """Recover coarse algorithm coverage from older approved-algorithm sections."""
    categories: Set[str] = set()

    for raw_line in section.splitlines():
        line = normalize_whitespace(raw_line)
        if not line:
            continue

        lower = line.lower()
        if lower in LEGACY_TABLE_HEADER_LINES:
            continue
        if lower.startswith("table "):
            continue
        if "non-approved" in lower:
            continue
        if "approved mode" in lower:
            continue

        categories.update(categorize_algorithm_entry(line))

    return sorted(categories)


def parse_algorithms_from_policy_text(policy_text: str) -> Tuple[List[str], List[str]]:
    """
    Parse detailed algorithm rows and simplified categories from policy text.

    The parser only looks at the 2.5 Algorithms section so it ignores vendor
    contact data and other CMVP page boilerplate.
    """
    section = extract_algorithm_section(policy_text)
    if not section:
        legacy_section = extract_legacy_algorithm_section(policy_text)
        if not legacy_section:
            return [], []
        return [], parse_categories_from_legacy_section(legacy_section)

    entries: List[str] = []
    categories: Set[str] = set()
    current_parts: List[str] = []

    for raw_line in section.splitlines():
        line = normalize_whitespace(raw_line)
        if is_policy_noise_line(line):
            continue

        if is_algorithm_entry_start(line):
            if current_parts:
                entry = format_algorithm_entry(current_parts)
                if entry and entry not in entries:
                    entries.append(entry)
                    categories.update(categorize_algorithm_entry(entry))
            current_parts = [line]
            continue

        if current_parts:
            current_parts.append(line)

    if current_parts:
        entry = format_algorithm_entry(current_parts)
        if entry and entry not in entries:
            entries.append(entry)
            categories.update(categorize_algorithm_entry(entry))

    return normalize_string_list(entries), sorted(categories)


def is_markdown_table_separator(cells: List[str]) -> bool:
    """Return True when a markdown table row is just the --- separator."""
    return bool(cells) and all(cell and set(cell) <= {"-", ":", " "} for cell in cells)


def parse_algorithms_from_policy_markdown(markdown: str) -> Tuple[List[str], List[str]]:
    """Parse algorithm rows from markdown output for a Security Policy PDF."""
    section = extract_algorithm_section(markdown)
    if not section:
        return [], []

    entries: List[str] = []
    categories: Set[str] = set()

    for raw_line in section.splitlines():
        line = normalize_whitespace(raw_line)
        if not line.startswith("|") or line.count("|") < 2:
            continue

        cells = [
            normalize_whitespace(cell)
            for cell in line.strip().strip("|").split("|")
        ]
        if not any(cells) or is_markdown_table_separator(cells):
            continue
        if cells[0].lower() == "algorithm" or not cells[0]:
            continue

        entry = format_algorithm_entry(cells)
        if not is_algorithm_entry_start(entry) or entry in entries:
            continue

        entries.append(entry)
        categories.update(categorize_algorithm_entry(entry))

    if entries:
        return normalize_string_list(entries), sorted(categories)

    return parse_algorithms_from_policy_text(section)


# Backward-compatible name for tests and old callers from the Firecrawl era.
parse_algorithms_from_firecrawl_markdown = parse_algorithms_from_policy_markdown


def parse_algorithms_from_policy_pdf_bytes(pdf_bytes: bytes) -> Tuple[List[str], List[str]]:
    """Extract detailed and simplified algorithm lists from PDF bytes."""
    policy_text = extract_policy_text_from_pdf_bytes(pdf_bytes)
    return parse_algorithms_from_policy_text(policy_text)


def extract_markdown_text(markdown_payload) -> str:
    """Normalize Crawl4AI markdown payload variants to plain text."""
    if markdown_payload is None:
        return ""
    if isinstance(markdown_payload, str):
        return markdown_payload
    for attribute in ("raw_markdown", "markdown", "fit_markdown"):
        value = getattr(markdown_payload, attribute, None)
        if isinstance(value, str) and value:
            return value
    return str(markdown_payload)


def extract_text_from_crawl4ai_html(html: str) -> str:
    """Convert Crawl4AI's PDF HTML output into line-oriented policy text."""
    if not html:
        return ""

    soup = BeautifulSoup(html, "html.parser")
    lines = [
        normalize_whitespace(line)
        for line in soup.get_text("\n").splitlines()
        if normalize_whitespace(line)
    ]
    return "\n".join(lines)


def extract_text_from_crawl4ai_result(scrape_result) -> str:
    """Extract usable policy text from Crawl4AI PDF scrape result variants."""
    text = getattr(scrape_result, "text", "")
    if isinstance(text, str) and normalize_whitespace(text):
        return text

    for attribute in ("cleaned_html", "html"):
        html = getattr(scrape_result, attribute, "")
        if isinstance(html, str):
            policy_text = extract_text_from_crawl4ai_html(html)
            if policy_text:
                return policy_text

    return ""


def extract_text_from_crawl4ai_process_result(process_result) -> str:
    """Extract raw page text from Crawl4AI's PDF processor result."""
    pages = getattr(process_result, "pages", []) or []
    page_text = [
        getattr(page, "raw_text", "") or getattr(page, "markdown", "")
        for page in pages
    ]
    return "\n".join(text for text in page_text if text)


def scrape_crawl4ai_policy_text(url: str) -> str:
    """Run Crawl4AI's PDF processor while preserving raw table line breaks."""
    strategy = PDFContentScrapingStrategy(batch_size=8)
    pdf_path = strategy._get_pdf_path(url)
    try:
        process_result = strategy.pdf_processor.process_batch(Path(pdf_path))
        policy_text = extract_text_from_crawl4ai_process_result(process_result)
        if policy_text:
            return policy_text

        scrape_result = strategy.scrap(pdf_path, "")
        return extract_text_from_crawl4ai_result(scrape_result)
    finally:
        if url.startswith(("http://", "https://")):
            try:
                Path(pdf_path).unlink(missing_ok=True)
            except OSError:
                pass


async def fetch_with_retry(
    client: httpx.AsyncClient,
    url: str,
    response_type: str = "text",
    retries: int = 3,
) -> Optional[object]:
    """Fetch a URL asynchronously with retries for transient failures."""
    for attempt in range(retries):
        try:
            response = await client.get(url)
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", "30"))
                print(f"Rate limited on {url}, waiting {retry_after}s...", file=sys.stderr)
                await asyncio.sleep(retry_after)
                continue
            response.raise_for_status()
            return response.text if response_type == "text" else response.content
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500 or attempt == retries - 1:
                print(f"Error fetching {url}: {exc}", file=sys.stderr)
                return None
            wait = 2 ** (attempt + 1)
            print(f"Attempt {attempt + 1}/{retries} failed for {url}: {exc}. Retrying in {wait}s...", file=sys.stderr)
            await asyncio.sleep(wait)
        except httpx.RequestError as exc:
            if attempt == retries - 1:
                print(f"Error fetching {url}: {exc}", file=sys.stderr)
                return None
            wait = 2 ** (attempt + 1)
            print(f"Attempt {attempt + 1}/{retries} failed for {url}: {exc}. Retrying in {wait}s...", file=sys.stderr)
            await asyncio.sleep(wait)
    return None


async def fetch_policy_pdf_bytes(
    client: httpx.AsyncClient,
    url: str,
    pdf_cache: Dict[str, asyncio.Task],
    pdf_cache_lock: asyncio.Lock,
) -> Tuple[Optional[bytes], bool]:
    """Fetch Security Policy PDF bytes through an in-run task cache."""
    async with pdf_cache_lock:
        task = pdf_cache.get(url)
        cache_hit = task is not None
        if task is None:
            task = asyncio.create_task(fetch_with_retry(client, url, response_type="bytes"))
            pdf_cache[url] = task

    result = await asyncio.shield(task)
    return result if isinstance(result, bytes) else None, cache_hit


async def fetch_crawl4ai_policy_text(
    url: str,
    retries: int = 1,
) -> Optional[str]:
    """Fetch text for a Security Policy PDF with Crawl4AI's local PDF strategy."""
    if not CRAWL4AI_AVAILABLE:
        return None

    for attempt in range(retries):
        try:
            policy_text = await asyncio.to_thread(scrape_crawl4ai_policy_text, url)
            if policy_text:
                return policy_text

            print(f"Warning: Crawl4AI returned no policy text for {url}", file=sys.stderr)
            return None
        except Exception as exc:
            if attempt == retries - 1:
                print(f"Error scraping {url} with Crawl4AI: {exc}", file=sys.stderr)
                return None
            wait = 2 ** (attempt + 1)
            print(
                f"Attempt {attempt + 1}/{retries} failed for Crawl4AI scrape {url}: {exc}. Retrying in {wait}s...",
                file=sys.stderr,
            )
            await asyncio.sleep(wait)

    return None


def import_algorithms_from_database(db_path: str) -> Dict[int, List[str]]:
    """
    Import algorithm data from an existing CMVP database.

    Args:
        db_path: Path to the cmvp.db SQLite database

    Returns:
        Dictionary mapping certificate numbers to lists of algorithms
    """
    algorithms_map = {}

    if not os.path.exists(db_path):
        print(f"Warning: Database not found at {db_path}", file=sys.stderr)
        return algorithms_map

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if the table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificate_algorithms'")
        if not cursor.fetchone():
            print("Warning: certificate_algorithms table not found in database", file=sys.stderr)
            conn.close()
            return algorithms_map

        # Fetch all algorithm data
        cursor.execute("SELECT cert_number, algorithm_name FROM certificate_algorithms ORDER BY cert_number")
        rows = cursor.fetchall()

        for cert_num, algo_name in rows:
            if cert_num not in algorithms_map:
                algorithms_map[cert_num] = []
            algorithms_map[cert_num].append(algo_name)

        conn.close()
        print(f"Imported algorithms for {len(algorithms_map)} certificates from database")

    except Exception as e:
        print(f"Error importing from database: {e}", file=sys.stderr)

    return algorithms_map


async def fetch_certificate_algorithms(
    client: httpx.AsyncClient,
    security_policy_url: Optional[str],
    fallback_url: Optional[str],
    pdf_semaphore: asyncio.Semaphore,
    algorithm_source: str,
    pdf_cache: Dict[str, asyncio.Task],
    pdf_cache_lock: asyncio.Lock,
) -> AlgorithmExtractionResult:
    """Fetch and parse a certificate's Security Policy using the configured source."""
    attempts: List[Dict[str, str]] = []
    pdf_cache_hits = 0

    for candidate in normalize_string_list([security_policy_url, fallback_url]):
        if algorithm_source == CRAWL4AI_ALGORITHM_SOURCE and CRAWL4AI_AVAILABLE:
            attempt = {
                "source": CRAWL4AI_ALGORITHM_SOURCE,
                "url": candidate,
                "status": "started",
            }
            async with pdf_semaphore:
                policy_text = await fetch_crawl4ai_policy_text(candidate)
            if policy_text:
                try:
                    detailed, categories = parse_algorithms_from_policy_text(policy_text)
                    if detailed or categories:
                        attempt["status"] = "parsed"
                        attempts.append(attempt)
                        return AlgorithmExtractionResult(
                            detailed=detailed,
                            categories=categories,
                            parsed=True,
                            source=CRAWL4AI_ALGORITHM_SOURCE,
                            source_url=candidate,
                            attempts=attempts,
                        )
                    attempt["status"] = "no_algorithms"
                    attempts.append(attempt)
                    print(
                        f"Warning: Crawl4AI returned policy text for {candidate} but no algorithm rows were found; "
                        "falling back to local PDF parsing.",
                        file=sys.stderr,
                    )
                except Exception as exc:
                    attempt["status"] = "parse_error"
                    attempt["error"] = str(exc)[:200]
                    attempts.append(attempt)
                    print(f"Warning: Failed to parse Crawl4AI policy text for {candidate}: {exc}", file=sys.stderr)
            else:
                attempt["status"] = "no_text"
                attempts.append(attempt)

        local_attempt = {
            "source": SECURITY_POLICY_ALGORITHM_SOURCE,
            "url": candidate,
            "status": "started",
        }
        async with pdf_semaphore:
            pdf_bytes, cache_hit = await fetch_policy_pdf_bytes(
                client,
                candidate,
                pdf_cache,
                pdf_cache_lock,
            )
        if cache_hit:
            pdf_cache_hits += 1
            local_attempt["cache_hit"] = "true"
        if not pdf_bytes:
            local_attempt["status"] = "fetch_failed"
            attempts.append(local_attempt)
            continue

        try:
            detailed, categories = parse_algorithms_from_policy_pdf_bytes(pdf_bytes)
            if detailed or categories:
                local_attempt["status"] = "parsed"
                attempts.append(local_attempt)
                return AlgorithmExtractionResult(
                    detailed=detailed,
                    categories=categories,
                    parsed=True,
                    source=SECURITY_POLICY_ALGORITHM_SOURCE,
                    source_url=candidate,
                    fallback_used=any(
                        attempt.get("source") == CRAWL4AI_ALGORITHM_SOURCE
                        for attempt in attempts
                    ),
                    pdf_cache_hits=pdf_cache_hits,
                    attempts=attempts,
                )
            local_attempt["status"] = "no_algorithms"
            attempts.append(local_attempt)
        except Exception as exc:
            local_attempt["status"] = "parse_error"
            local_attempt["error"] = str(exc)[:200]
            attempts.append(local_attempt)
            print(f"Warning: Failed to parse Security Policy PDF {candidate}: {exc}", file=sys.stderr)

    return AlgorithmExtractionResult(
        detailed=[],
        categories=[],
        parsed=False,
        source="none",
        fallback_used=any(
            attempt.get("source") == CRAWL4AI_ALGORITHM_SOURCE
            for attempt in attempts
        ),
        pdf_cache_hits=pdf_cache_hits,
        attempts=attempts,
    )


async def process_certificate_record(
    module: Dict,
    dataset: str,
    generated_at: str,
    algorithm_source: str,
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
    previous_metadata: Dict,
    client: httpx.AsyncClient,
    cert_semaphore: asyncio.Semaphore,
    pdf_semaphore: asyncio.Semaphore,
    pdf_cache: Dict[str, asyncio.Task],
    pdf_cache_lock: asyncio.Lock,
    database_algorithms_map: Dict[int, List[str]],
) -> Tuple[Dict, Optional[Dict], List[str], Dict[str, int]]:
    """Process one module row into an enriched module row and optional detail payload."""
    stats = new_processing_stats()

    cert_number = parse_certificate_number(module)
    module_out = dict(previous_module or {})
    module_out.update(module)

    if cert_number is None:
        strip_algorithm_fields(module_out)
        apply_algorithm_extraction_provenance(
            module_out,
            build_algorithm_extraction_provenance(
                algorithm_source,
                "skipped",
                "none",
                None,
                [],
                [],
            ),
        )
        module_out["detail_available"] = False
        return module_out, None, [], stats

    current_fingerprint = build_certificate_fingerprint(module, dataset)
    previous_fingerprint = build_certificate_fingerprint(previous_module, dataset) if previous_module else None
    fingerprint_matches = should_reuse_certificate_detail(
        previous_module,
        previous_detail,
        previous_fingerprint,
        current_fingerprint,
    )

    detail_payload: Optional[Dict] = None
    if fingerprint_matches:
        detail_payload = prepare_reused_detail_payload(
            previous_detail,
            module,
            cert_number,
            dataset,
            generated_at,
        )
        stats["html_reused"] += 1
    else:
        async with cert_semaphore:
            html = await fetch_with_retry(client, get_certificate_detail_url(cert_number))
        if html:
            try:
                detail_payload = parse_certificate_detail_page(
                    html,
                    cert_number,
                    summary_module=module,
                    dataset=dataset,
                    generated_at=generated_at,
                )
                stats["html_refreshed"] += 1
            except Exception as exc:
                stats["html_failed"] += 1
                print(f"Warning: Failed to parse certificate {cert_number}: {exc}", file=sys.stderr)
        else:
            stats["html_failed"] += 1

    if detail_payload:
        module_out = dict(previous_module or {})
        module_out.update(module)
        for key in MODULE_DETAIL_FIELDS:
            value = detail_payload.get(key)
            if value not in (None, [], "", {}):
                module_out[key] = value
        module_out["security_policy_url"] = detail_payload.get("security_policy_url") or module_out.get("security_policy_url")
    else:
        strip_algorithm_fields(module_out)

    trusted_algorithm_reuse = should_reuse_cached_algorithms(
        algorithm_source,
        fingerprint_matches,
        previous_metadata,
        previous_module,
        previous_detail,
    )

    if algorithm_source == "database":
        categories = normalize_string_list(database_algorithms_map.get(cert_number, []))
        detailed: List[str] = []
        extraction_status = "parsed" if categories else "miss"
        extraction_provenance = build_algorithm_extraction_provenance(
            algorithm_source,
            extraction_status,
            "database",
            None,
            categories,
            detailed,
        )
        stats["algorithm_source_database"] += 1
        if categories:
            stats["algorithm_successes"] += 1
        else:
            stats["algorithm_misses"] += 1
        if detail_payload:
            apply_algorithm_fields(detail_payload, categories, detailed)
            apply_algorithm_extraction_provenance(detail_payload, extraction_provenance, include_attempts=True)
        apply_algorithm_fields(module_out, categories, detailed)
        apply_algorithm_extraction_provenance(module_out, extraction_provenance)
    elif algorithm_source in CACHEABLE_ALGORITHM_SOURCES:
        detailed, categories = ([], [])
        if trusted_algorithm_reuse:
            categories, detailed = cached_algorithm_fields(previous_module, previous_detail)
            stats["pdf_reused"] += 1
            stats["algorithm_cache_hits"] += 1
            cached_source, cached_source_url = cached_algorithm_extraction_source(
                previous_module,
                previous_detail,
                previous_metadata,
            )
            extraction_provenance = build_algorithm_extraction_provenance(
                algorithm_source,
                "cached",
                cached_source,
                cached_source_url,
                categories,
                detailed,
                cached=True,
            )
            if categories or detailed:
                stats["algorithm_successes"] += 1
        else:
            if detail_payload:
                strip_algorithm_fields(detail_payload)
            strip_algorithm_fields(module_out)
            extraction_result = await fetch_certificate_algorithms(
                client,
                (detail_payload or {}).get("security_policy_url") or module.get("security_policy_url"),
                get_security_policy_url(cert_number),
                pdf_semaphore,
                algorithm_source,
                pdf_cache,
                pdf_cache_lock,
            )
            detailed = extraction_result.detailed
            categories = extraction_result.categories
            stats["pdf_cache_hits"] += extraction_result.pdf_cache_hits
            extraction_provenance = build_algorithm_extraction_provenance(
                algorithm_source,
                "parsed" if extraction_result.parsed else "miss",
                extraction_result.source,
                extraction_result.source_url,
                categories,
                detailed,
                fallback_used=extraction_result.fallback_used,
                attempts=extraction_result.attempts,
            )
            if extraction_result.parsed:
                stats["pdf_refreshed"] += 1
                stats["algorithm_successes"] += 1
                if extraction_result.source == CRAWL4AI_ALGORITHM_SOURCE:
                    stats["algorithm_source_crawl4ai"] += 1
                elif extraction_result.source == SECURITY_POLICY_ALGORITHM_SOURCE:
                    stats["algorithm_source_security_policy_pdf"] += 1
                if extraction_result.fallback_used:
                    stats["algorithm_fallbacks"] += 1
            else:
                stats["pdf_failed"] += 1
                stats["algorithm_misses"] += 1

        if detail_payload:
            apply_algorithm_fields(detail_payload, categories, detailed)
            apply_algorithm_extraction_provenance(detail_payload, extraction_provenance, include_attempts=True)
        apply_algorithm_fields(module_out, categories, detailed)
        apply_algorithm_extraction_provenance(module_out, extraction_provenance)
    else:
        extraction_provenance = build_algorithm_extraction_provenance(
            algorithm_source,
            "skipped",
            "none",
            None,
            [],
            [],
        )
        stats["algorithm_source_none"] += 1
        if detail_payload:
            strip_algorithm_fields(detail_payload)
            apply_algorithm_extraction_provenance(detail_payload, extraction_provenance, include_attempts=True)
        strip_algorithm_fields(module_out)
        apply_algorithm_extraction_provenance(module_out, extraction_provenance)

    module_out["detail_available"] = detail_payload is not None
    module_categories = normalize_string_list(module_out.get("algorithms", []))
    return module_out, detail_payload, module_categories, stats


def build_certificate_timeout_result(
    module: Dict,
    dataset: str,
    generated_at: str,
    algorithm_source: str,
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
    previous_metadata: Dict,
) -> Tuple[Dict, Optional[Dict], List[str], Dict[str, int]]:
    """Build a bounded fallback result when one certificate exceeds the timeout."""
    stats = new_processing_stats()
    stats["certificate_timeouts"] += 1

    cert_number = parse_certificate_number(module)
    module_out = dict(previous_module or {})
    module_out.update(module)

    source_url = module_out.get("security_policy_url")
    if cert_number is not None and not source_url:
        source_url = get_security_policy_url(cert_number)

    categories, detailed = cached_algorithm_fields(previous_module, previous_detail)
    attempt = {
        "source": algorithm_source,
        "url": str(source_url or ""),
        "status": "timeout",
    }

    detail_payload: Optional[Dict] = None
    if cert_number is not None and previous_detail:
        detail_payload = prepare_reused_detail_payload(
            previous_detail,
            module,
            cert_number,
            dataset,
            generated_at,
        )
        stats["html_reused"] += 1
        for key in MODULE_DETAIL_FIELDS:
            value = detail_payload.get(key)
            if value not in (None, [], "", {}):
                module_out[key] = value
        module_out["security_policy_url"] = detail_payload.get("security_policy_url") or module_out.get("security_policy_url")
        cached_source, cached_source_url = cached_algorithm_extraction_source(
            previous_module,
            previous_detail,
            previous_metadata,
        )
        provenance = build_algorithm_extraction_provenance(
            algorithm_source,
            "cached" if categories or detailed else "miss",
            cached_source if categories or detailed else "timeout",
            cached_source_url or source_url,
            categories,
            detailed,
            cached=bool(categories or detailed),
            attempts=[attempt],
        )
        if categories or detailed:
            stats["pdf_reused"] += 1
            stats["algorithm_cache_hits"] += 1
            stats["algorithm_successes"] += 1
        else:
            stats["algorithm_misses"] += 1
        apply_algorithm_fields(detail_payload, categories, detailed)
        apply_algorithm_extraction_provenance(detail_payload, provenance, include_attempts=True)
        apply_algorithm_fields(module_out, categories, detailed)
        apply_algorithm_extraction_provenance(module_out, provenance)
        module_out["detail_available"] = True
        return module_out, detail_payload, categories, stats

    stats["html_failed"] += 1
    if algorithm_source in CACHEABLE_ALGORITHM_SOURCES:
        stats["pdf_failed"] += 1
    if algorithm_source != "none":
        stats["algorithm_misses"] += 1
    strip_algorithm_fields(module_out)
    provenance = build_algorithm_extraction_provenance(
        algorithm_source,
        "miss",
        "timeout",
        source_url,
        [],
        [],
        attempts=[attempt],
    )
    apply_algorithm_extraction_provenance(module_out, provenance)
    module_out["detail_available"] = False
    return module_out, None, [], stats


async def process_certificate_record_with_timeout(
    index: int,
    module: Dict,
    dataset: str,
    generated_at: str,
    algorithm_source: str,
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
    previous_metadata: Dict,
    client: httpx.AsyncClient,
    cert_semaphore: asyncio.Semaphore,
    pdf_semaphore: asyncio.Semaphore,
    pdf_cache: Dict[str, asyncio.Task],
    pdf_cache_lock: asyncio.Lock,
    database_algorithms_map: Dict[int, List[str]],
) -> Tuple[int, Dict, Optional[Dict], List[str], Dict[str, int]]:
    """Process one certificate and return its input index, timing out slow records."""
    try:
        module_out, detail_payload, categories, stats = await asyncio.wait_for(
            process_certificate_record(
                module,
                dataset,
                generated_at,
                algorithm_source,
                previous_module,
                previous_detail,
                previous_metadata,
                client,
                cert_semaphore,
                pdf_semaphore,
                pdf_cache,
                pdf_cache_lock,
                database_algorithms_map,
            ),
            timeout=CERT_PROCESS_TIMEOUT,
        )
        return index, module_out, detail_payload, categories, stats
    except asyncio.TimeoutError:
        cert_number = parse_certificate_number(module)
        print(
            f"Warning: Timed out processing certificate {cert_number or 'unknown'} "
            f"after {CERT_PROCESS_TIMEOUT}s; preserving cached data when available.",
            file=sys.stderr,
        )
        module_out, detail_payload, categories, stats = build_certificate_timeout_result(
            module,
            dataset,
            generated_at,
            algorithm_source,
            previous_module,
            previous_detail,
            previous_metadata,
        )
        return index, module_out, detail_payload, categories, stats


async def build_certificate_artifacts(
    modules: List[Dict],
    dataset: str,
    generated_at: str,
    algorithm_source: str,
    previous_outputs: Dict[str, object],
    database_algorithms_map: Optional[Dict[int, List[str]]] = None,
) -> Tuple[List[Dict], Dict[int, Dict], Dict[int, List[str]], Dict[str, int]]:
    """Build enriched module rows, certificate detail payloads, and algorithms for a dataset."""
    previous_modules = previous_outputs.get("modules", {}).get(dataset, {})
    previous_details = previous_outputs.get("details", {})
    previous_metadata = previous_outputs.get("metadata", {})
    database_algorithms_map = database_algorithms_map or {}

    results: List[Optional[Dict]] = [None] * len(modules)
    payloads: Dict[int, Dict] = {}
    algorithms_map: Dict[int, List[str]] = {}
    stats = new_processing_stats()

    timeout = httpx.Timeout(30.0)
    cert_semaphore = asyncio.Semaphore(CERT_FETCH_CONCURRENCY)
    pdf_semaphore = asyncio.Semaphore(PDF_FETCH_CONCURRENCY)
    pdf_cache: Dict[str, asyncio.Task] = {}
    pdf_cache_lock = asyncio.Lock()

    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        timeout=timeout,
    ) as client:
        pending_tasks: Set[asyncio.Task] = set()
        next_index = 0
        task_window = max(CERT_FETCH_CONCURRENCY, PDF_FETCH_CONCURRENCY)

        def schedule_next_certificate() -> None:
            nonlocal next_index
            if next_index >= len(modules):
                return
            index = next_index
            module = modules[index]
            cert_number = parse_certificate_number(module)
            pending_tasks.add(
                asyncio.create_task(
                    process_certificate_record_with_timeout(
                        index,
                        module,
                        dataset,
                        generated_at,
                        algorithm_source,
                        previous_modules.get(cert_number) if cert_number is not None else None,
                        previous_details.get(cert_number) if cert_number is not None else None,
                        previous_metadata,
                        client,
                        cert_semaphore,
                        pdf_semaphore,
                        pdf_cache,
                        pdf_cache_lock,
                        database_algorithms_map,
                    )
                )
            )
            next_index += 1

        total = len(modules)
        for _ in range(min(task_window, total)):
            schedule_next_certificate()

        completed = 0
        while pending_tasks:
            done, pending_tasks = await asyncio.wait(
                pending_tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                index, module_out, detail_payload, categories, task_stats = await task
                completed += 1
                results[index] = module_out
                cert_number = parse_certificate_number(module_out)
                if cert_number is not None and detail_payload is not None:
                    payloads[cert_number] = detail_payload
                if cert_number is not None and categories:
                    algorithms_map[cert_number] = categories
                add_processing_stats(stats, task_stats)
                schedule_next_certificate()
                if completed % 100 == 0 or completed == total:
                    print(
                        f"  Progress: {completed}/{total} "
                        f"({stats['html_reused']} reused, {stats['html_refreshed']} refreshed, {stats['html_failed']} failed)"
                    )

    return [result or {} for result in results], payloads, algorithms_map, stats


def parse_modules_table(html: str) -> List[Dict]:
    """
    Parse the validated modules table from NIST CMVP HTML page.
    
    Args:
        html: HTML content of the page
        
    Returns:
        List of dictionaries containing module information
    """
    soup = BeautifulSoup(html, "lxml")
    modules = []
    
    # Find the table containing validated modules
    # The exact structure may vary, so we look for common patterns
    table = soup.find("table")
    
    if not table:
        print("Warning: No table found on page", file=sys.stderr)
        return modules
    
    # Extract headers
    headers = []
    thead = table.find("thead")
    if thead:
        header_row = thead.find("tr")
        if header_row:
            headers = [th.get_text(strip=True) for th in header_row.find_all(["th", "td"])]
    
    # If no thead, try to get headers from first row
    if not headers:
        tbody = table.find("tbody")
        if tbody:
            first_row = tbody.find("tr")
        else:
            first_row = table.find("tr")
        
        if first_row:
            # Check if first row looks like headers
            cells = first_row.find_all(["th", "td"])
            if cells and cells[0].name == "th":
                headers = [cell.get_text(strip=True) for cell in cells]
    
    # Extract data rows
    tbody = table.find("tbody")
    rows = tbody.find_all("tr") if tbody else table.find_all("tr")
    
    # Skip header row if it's included in rows
    start_idx = 1 if (not thead and headers and rows and 
                      all(cell.name == "th" for cell in rows[0].find_all(["th", "td"]))) else 0
    
    for row in rows[start_idx:]:
        cells = row.find_all(["td", "th"])
        if not cells:
            continue
        
        # Create module dictionary
        module = {}
        
        for idx, cell in enumerate(cells):
            # Use header as key if available, otherwise use index
            key = headers[idx] if idx < len(headers) and headers[idx] else f"column_{idx}"
            
            # Extract text content
            text = cell.get_text(strip=True)
            
            # Extract links if present
            link = cell.find("a")
            if link and link.get("href"):
                href = link.get("href")
                # Make absolute URL if relative
                if href.startswith("/"):
                    href = f"https://csrc.nist.gov{href}"
                module[f"{key}_url"] = href
            
            module[key] = text
        
        if module:  # Only add non-empty modules
            modules.append(module)
    
    return modules


def scrape_all_modules() -> List[Dict]:
    """
    Scrape all validated modules from NIST CMVP.
    
    Returns:
        List of all modules found
    """
    all_modules = []
    
    # Construct the search URL using BASE_URL and SEARCH_PATH
    url = f"{BASE_URL}{SEARCH_PATH}"
    print(f"Fetching: {url}")
    print(f"Note: If this URL is incorrect, set NIST_SEARCH_PATH environment variable")
    
    html = fetch_page(url)
    if not html:
        print("Failed to fetch main page", file=sys.stderr)
        print(f"Verify the URL is correct: {url}", file=sys.stderr)
        return all_modules
    
    modules = parse_modules_table(html)
    all_modules.extend(modules)
    
    print(f"Found {len(modules)} modules on page")
    
    # Note: If the site uses pagination, we would need to detect and follow
    # "next page" links here. For now, we're assuming all results are on one page
    # or implementing basic pagination detection.
    
    return all_modules


def scrape_historical_modules() -> List[Dict]:
    """
    Scrape historical modules from NIST CMVP.
    
    Returns:
        List of all historical modules found
    """
    all_modules = []
    
    # Construct the URL for historical modules
    url = f"{BASE_URL}{HISTORICAL_SEARCH_PARAMS}"
    print(f"Fetching historical modules: {url}")
    
    html = fetch_page(url)
    if not html:
        print("Failed to fetch historical modules page", file=sys.stderr)
        print(f"Verify the URL is correct: {url}", file=sys.stderr)
        return all_modules
    
    modules = parse_modules_table(html)
    all_modules.extend(modules)
    
    print(f"Found {len(modules)} historical modules on page")
    
    return all_modules


def scrape_modules_in_process() -> List[Dict]:
    """
    Scrape modules in process from NIST CMVP.
    
    Returns:
        List of all modules in process found
    """
    print(f"Fetching: {MODULES_IN_PROCESS_URL}")
    
    html = fetch_page(MODULES_IN_PROCESS_URL)
    if not html:
        print("Failed to fetch modules in process page", file=sys.stderr)
        print(f"Verify the URL is correct: {MODULES_IN_PROCESS_URL}", file=sys.stderr)
        return []
    
    modules = parse_modules_table(html)
    
    print(f"Found {len(modules)} modules in process on page")
    
    return modules


def save_json(data: Dict, filepath: str) -> None:
    """
    Save data to a JSON file.
    
    Args:
        data: Data to save
        filepath: Path to output file
    """
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"Saved: {filepath}")


def save_text(content: str, filepath: str) -> None:
    """
    Save UTF-8 text content to a file.

    Args:
        content: Text to save
        filepath: Path to output file
    """
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Saved: {filepath}")


def enrich_modules_with_urls(modules: List[Dict]) -> List[Dict]:
    """
    Add security policy URLs and certificate detail URLs to modules.

    Args:
        modules: List of module dictionaries

    Returns:
        List of modules with added URL fields
    """
    for module in modules:
        cert_num_str = module.get("Certificate Number", "")
        if cert_num_str:
            try:
                cert_num = int(cert_num_str)
                module["security_policy_url"] = get_security_policy_url(cert_num)
                module["certificate_detail_url"] = get_certificate_detail_url(cert_num)
            except ValueError:
                pass
    return modules


def enrich_modules_with_algorithms(modules: List[Dict], algorithms_map: Dict[int, List[str]]) -> List[Dict]:
    """
    Add algorithms to modules from the algorithms map.

    Args:
        modules: List of module dictionaries
        algorithms_map: Dictionary mapping certificate numbers to algorithm lists

    Returns:
        List of modules with added algorithms field
    """
    for module in modules:
        cert_num_str = module.get("Certificate Number", "")
        if cert_num_str:
            try:
                cert_num = int(cert_num_str)
                if cert_num in algorithms_map:
                    module["algorithms"] = algorithms_map[cert_num]
            except ValueError:
                pass
    return modules


def enrich_modules_with_details(modules: List[Dict], details_map: Dict[int, Dict]) -> List[Dict]:
    """
    Add selected certificate detail fields to modules from the details map.

    Args:
        modules: List of module dictionaries
        details_map: Dictionary mapping certificate numbers to detail dictionaries

    Returns:
        List of modules with added detail fields
    """
    for module in modules:
        cert_num = parse_certificate_number(module)
        if cert_num is None or cert_num not in details_map:
            continue

        details = details_map[cert_num]
        for key in MODULE_DETAIL_FIELDS:
            value = details.get(key)
            if value not in (None, [], "", {}):
                module[key] = value
    return modules


def create_algorithms_summary(algorithms_map: Dict[int, List[str]]) -> Dict:
    """
    Create a summary of all algorithms across all certificates.

    Args:
        algorithms_map: Dictionary mapping certificate numbers to algorithm lists

    Returns:
        Dictionary with algorithm statistics
    """
    algo_counts = {}
    for cert_num, algos in algorithms_map.items():
        for algo in algos:
            if algo not in algo_counts:
                algo_counts[algo] = {"count": 0, "certificates": []}
            algo_counts[algo]["count"] += 1
            algo_counts[algo]["certificates"].append(cert_num)

    # Sort by count descending
    sorted_algos = dict(sorted(algo_counts.items(), key=lambda x: x[1]["count"], reverse=True))

    return {
        "total_unique_algorithms": len(sorted_algos),
        "total_certificate_algorithm_pairs": sum(len(algos) for algos in algorithms_map.values()),
        "algorithms": sorted_algos
    }


def normalize_index_list(value) -> List[str]:
    """Normalize a scalar or list value for compact index payloads."""
    if isinstance(value, list):
        return normalize_string_list(value)
    if value in (None, "", [], {}):
        return []
    text = normalize_whitespace(str(value))
    return [text] if text else []


def first_non_empty(*values):
    """Return the first value that carries meaningful content."""
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def build_certificate_index_entry(
    module: Dict,
    dataset: str,
    detail_payload: Optional[Dict] = None,
) -> Optional[Dict]:
    """Build one compact certificate discovery row."""
    detail_payload = detail_payload or {}
    cert_number = parse_certificate_number(detail_payload) or parse_certificate_number(module)
    if cert_number is None:
        return None

    algorithms = normalize_string_list(
        detail_payload.get("algorithms") or module.get("algorithms") or []
    )
    validation_date = first_non_empty(
        detail_payload.get("validation_date"),
        module.get("Validation Date"),
    )
    validation_dates = normalize_index_list(detail_payload.get("validation_dates"))
    if not validation_dates and validation_date:
        validation_dates = normalize_index_list(validation_date)

    extraction = first_non_empty(
        detail_payload.get("algorithm_extraction"),
        module.get("algorithm_extraction"),
    )
    if not isinstance(extraction, dict):
        extraction = {}

    path = f"/api/certificates/{cert_number}.json"
    certificate_detail_url = first_non_empty(
        detail_payload.get("certificate_detail_url"),
        module.get("certificate_detail_url"),
        get_certificate_detail_url(cert_number),
    )

    return {
        "certificate_number": str(cert_number),
        "dataset": dataset,
        "path": path,
        "nist_page_url": first_non_empty(
            detail_payload.get("nist_page_url"),
            certificate_detail_url,
            get_certificate_detail_url(cert_number),
        ),
        "certificate_detail_url": certificate_detail_url,
        "security_policy_url": first_non_empty(
            detail_payload.get("security_policy_url"),
            module.get("security_policy_url"),
        ),
        "vendor_name": first_non_empty(
            detail_payload.get("vendor_name"),
            module.get("Vendor Name"),
        ),
        "module_name": first_non_empty(
            detail_payload.get("module_name"),
            module.get("Module Name"),
        ),
        "standard": first_non_empty(
            detail_payload.get("standard"),
            module.get("standard"),
            module.get("Standard"),
        ),
        "status": first_non_empty(
            detail_payload.get("status"),
            module.get("status"),
            module.get("Status"),
        ),
        "module_type": first_non_empty(
            detail_payload.get("module_type"),
            module.get("module_type"),
            module.get("Module Type"),
        ),
        "overall_level": first_non_empty(
            detail_payload.get("overall_level"),
            module.get("overall_level"),
        ),
        "validation_date": validation_date,
        "validation_dates": validation_dates,
        "sunset_date": first_non_empty(
            detail_payload.get("sunset_date"),
            module.get("sunset_date"),
        ),
        "algorithms": algorithms,
        "algorithm_count": len(algorithms),
        "algorithm_extraction_status": extraction.get("status"),
        "algorithm_source": extraction.get("source"),
        "detail_available": bool(detail_payload) or module.get("detail_available") is True,
    }


def build_certificate_index_payload(
    metadata: Dict,
    modules: List[Dict],
    historical_modules: List[Dict],
    detail_payloads: Optional[Dict[int, Dict]] = None,
) -> Dict:
    """Build a compact discovery index for all per-certificate JSON files."""
    detail_payloads = detail_payloads or {}
    entries: List[Dict] = []

    for dataset, records in (("active", modules), ("historical", historical_modules)):
        for module in records:
            cert_number = parse_certificate_number(module)
            entry = build_certificate_index_entry(
                module,
                dataset,
                detail_payloads.get(cert_number) if cert_number is not None else None,
            )
            if entry:
                entries.append(entry)

    entries.sort(key=lambda item: int(item["certificate_number"]))

    return {
        "metadata": metadata,
        "total_certificates": len(entries),
        "certificate_paths": {
            entry["certificate_number"]: entry["path"]
            for entry in entries
        },
        "certificates": entries,
    }


def parse_generated_at(value: Optional[str]) -> Optional[datetime]:
    """Parse the scraper timestamp format used in metadata."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def next_weekly_run_after(value: Optional[str]) -> Optional[str]:
    """Return the next Sunday 02:00 UTC run after the given timestamp."""
    generated_at = parse_generated_at(value)
    if generated_at is None:
        return None
    generated_at = generated_at.astimezone(timezone.utc)
    days_until_sunday = (6 - generated_at.weekday()) % 7
    candidate = generated_at.replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=days_until_sunday)
    if candidate <= generated_at:
        candidate += timedelta(days=7)
    return candidate.strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_ratio(numerator: int, denominator: int) -> Optional[float]:
    """Return a rounded ratio when the denominator is non-zero."""
    if denominator <= 0:
        return None
    return round(numerator / denominator, 6)


def build_quality_check(name: str, passed: bool, value, threshold=None) -> Dict:
    """Build one data-quality monitor check."""
    check = {
        "name": name,
        "status": "pass" if passed else "warn",
        "value": value,
    }
    if threshold is not None:
        check["threshold"] = threshold
    return check


def certificate_refresh_reason(
    module: Dict,
    dataset: str,
    previous_module: Optional[Dict],
    previous_detail: Optional[Dict],
    full_refresh: bool = FULL_REFRESH,
) -> Optional[str]:
    """Explain why the latest run could not reuse a cached certificate detail."""
    if full_refresh:
        return "full_refresh"
    if previous_module is None:
        return "new_certificate"
    if previous_detail is None:
        return "missing_cached_detail"

    current_fingerprint = build_certificate_fingerprint(module, dataset)
    previous_fingerprint = build_certificate_fingerprint(previous_module, dataset)
    if previous_fingerprint != current_fingerprint:
        return "summary_changed"

    missing_fields = [
        field
        for field in DETAIL_SCHEMA_REQUIRED_FIELDS
        if field not in previous_detail
    ]
    if missing_fields:
        return "cached_detail_schema_gap"
    return None


def changed_fingerprint_fields(module: Dict, previous_module: Optional[Dict]) -> List[Dict]:
    """Return summary fields that changed since the previous output."""
    if not previous_module:
        return []
    changes = []
    for field in CACHE_FINGERPRINT_FIELDS:
        previous_value = previous_module.get(field)
        current_value = module.get(field)
        if previous_value == current_value:
            continue
        changes.append(
            {
                "field": field,
                "previous": previous_value,
                "current": current_value,
            }
        )
    return changes


def quality_certificate_record(
    module: Dict,
    dataset: str,
    detail_payload: Optional[Dict] = None,
    reason: Optional[str] = None,
) -> Dict:
    """Build a compact certificate reference for quality reports."""
    detail_payload = detail_payload or {}
    cert_number = parse_certificate_number(detail_payload) or parse_certificate_number(module)
    record = {
        "certificate_number": str(cert_number) if cert_number is not None else None,
        "dataset": dataset,
        "path": f"/api/certificates/{cert_number}.json" if cert_number is not None else None,
        "vendor_name": first_non_empty(detail_payload.get("vendor_name"), module.get("Vendor Name")),
        "module_name": first_non_empty(detail_payload.get("module_name"), module.get("Module Name")),
        "standard": first_non_empty(detail_payload.get("standard"), module.get("standard"), module.get("Standard")),
        "status": first_non_empty(detail_payload.get("status"), module.get("status"), module.get("Status")),
    }
    if reason:
        record["reason"] = reason
    return record


def build_update_monitor(metadata: Dict, combined_metrics: Dict[str, int]) -> Dict:
    """Build a small run-health summary that can be monitored after each update."""
    html_total = (
        combined_metrics.get("html_reused", 0)
        + combined_metrics.get("html_refreshed", 0)
        + combined_metrics.get("html_failed", 0)
    )
    algorithm_total = (
        combined_metrics.get("algorithm_successes", 0)
        + combined_metrics.get("algorithm_misses", 0)
    )
    html_reuse_rate = safe_ratio(combined_metrics.get("html_reused", 0), html_total)
    algorithm_success_rate = safe_ratio(combined_metrics.get("algorithm_successes", 0), algorithm_total)

    checks = [
        build_quality_check(
            "html_cache_reuse_rate",
            html_reuse_rate is None or html_reuse_rate >= 0.9,
            html_reuse_rate,
            0.9,
        ),
        build_quality_check(
            "html_failures",
            combined_metrics.get("html_failed", 0) == 0,
            combined_metrics.get("html_failed", 0),
            0,
        ),
        build_quality_check(
            "certificate_timeouts",
            combined_metrics.get("certificate_timeouts", 0) == 0,
            combined_metrics.get("certificate_timeouts", 0),
            0,
        ),
        build_quality_check(
            "algorithm_success_rate",
            metadata.get("algorithm_source") == "none"
            or algorithm_success_rate is None
            or algorithm_success_rate >= 0.9,
            algorithm_success_rate,
            0.9,
        ),
        build_quality_check(
            "algorithm_source_supported",
            metadata.get("algorithm_source") != "firecrawl",
            metadata.get("algorithm_source"),
        ),
    ]

    return {
        "status": "pass" if all(check["status"] == "pass" for check in checks) else "warn",
        "schedule": "0 2 * * 0",
        "schedule_description": "Weekly on Sunday at 02:00 UTC",
        "latest_run_generated_at": metadata.get("generated_at"),
        "next_scheduled_run": next_weekly_run_after(metadata.get("generated_at")),
        "latest_run_metrics": combined_metrics,
        "checks": checks,
    }


def build_data_quality_report(
    metadata: Dict,
    modules: List[Dict],
    historical_modules: List[Dict],
    detail_payloads: Dict[int, Dict],
    previous_outputs: Dict[str, object],
    active_stats: Dict[str, int],
    historical_stats: Dict[str, int],
) -> Dict:
    """Build a compact report of misses, refreshes, fallbacks, and changed certs."""
    previous_modules = previous_outputs.get("modules", {}) if isinstance(previous_outputs, dict) else {}
    previous_details = previous_outputs.get("details", {}) if isinstance(previous_outputs, dict) else {}
    extraction_metrics = metadata.get("extraction_metrics") or build_extraction_metrics(active_stats, historical_stats)
    combined_metrics = extraction_metrics.get("combined") or combine_processing_stats(active_stats, historical_stats)

    misses: List[Dict] = []
    refreshed_records: List[Dict] = []
    fallback_usage: List[Dict] = []
    changed_certificates: List[Dict] = []

    for dataset, records in (("active", modules), ("historical", historical_modules)):
        dataset_previous_modules = previous_modules.get(dataset, {}) if isinstance(previous_modules, dict) else {}
        for module in records:
            cert_number = parse_certificate_number(module)
            detail_payload = detail_payloads.get(cert_number) if cert_number is not None else None
            previous_module = dataset_previous_modules.get(cert_number) if cert_number is not None else None
            previous_detail = previous_details.get(cert_number) if cert_number is not None and isinstance(previous_details, dict) else None

            refresh_reason = certificate_refresh_reason(
                module,
                dataset,
                previous_module,
                previous_detail,
            )
            if refresh_reason and detail_payload:
                refresh_record = quality_certificate_record(module, dataset, detail_payload, refresh_reason)
                field_changes = changed_fingerprint_fields(module, previous_module)
                if field_changes:
                    refresh_record["changed_fields"] = field_changes
                if refresh_reason == "cached_detail_schema_gap" and previous_detail:
                    refresh_record["missing_fields"] = [
                        field
                        for field in DETAIL_SCHEMA_REQUIRED_FIELDS
                        if field not in previous_detail
                    ]
                refreshed_records.append(refresh_record)
                if refresh_reason in {"new_certificate", "summary_changed"}:
                    changed_certificates.append(refresh_record)

            if module.get("detail_available") is not True:
                misses.append(quality_certificate_record(module, dataset, detail_payload, "certificate_detail_unavailable"))

            extraction = first_non_empty(
                (detail_payload or {}).get("algorithm_extraction"),
                module.get("algorithm_extraction"),
            )
            if not isinstance(extraction, dict):
                continue

            if extraction.get("status") == "miss":
                miss_record = quality_certificate_record(module, dataset, detail_payload, "algorithm_extraction_miss")
                miss_record["source"] = extraction.get("source")
                miss_record["source_url"] = extraction.get("source_url")
                misses.append(miss_record)

            attempts = extraction.get("attempts") or []
            if extraction.get("fallback_used") is True or len(attempts) > 1:
                fallback_record = quality_certificate_record(module, dataset, detail_payload, "algorithm_extraction_fallback")
                fallback_record["source"] = extraction.get("source")
                fallback_record["source_url"] = extraction.get("source_url")
                fallback_record["attempts"] = attempts
                fallback_usage.append(fallback_record)

    return {
        "metadata": metadata,
        "summary": {
            "misses": len(misses),
            "refreshed_records": len(refreshed_records),
            "fallback_usage": len(fallback_usage),
            "changed_certificates": len(changed_certificates),
        },
        "update_monitor": build_update_monitor(metadata, combined_metrics),
        "misses": misses,
        "refreshed_records": refreshed_records,
        "fallback_usage": fallback_usage,
        "changed_certificates": changed_certificates,
    }


def compact_search_index_reference(entry: Dict) -> Dict:
    """Return a compact certificate reference for search-friendly indexes."""
    return {
        "certificate_number": entry.get("certificate_number"),
        "dataset": entry.get("dataset"),
        "path": entry.get("path"),
        "vendor_name": entry.get("vendor_name"),
        "module_name": entry.get("module_name"),
        "standard": entry.get("standard"),
        "status": entry.get("status"),
        "algorithm_count": entry.get("algorithm_count", 0),
    }


def sorted_index_keys(index: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
    """Sort search-index keys and certificate references deterministically."""
    return {
        key: sorted(values, key=lambda item: int(item["certificate_number"]))
        for key, values in sorted(index.items(), key=lambda item: item[0].casefold())
    }


def build_search_index_payload(name: str, field: str, metadata: Dict, certificates: List[Dict]) -> Dict:
    """Build one search-friendly certificate index split."""
    index: Dict[str, List[Dict]] = {}
    for entry in certificates:
        if field == "algorithms":
            keys = normalize_string_list(entry.get("algorithms") or [])
        else:
            key_value = first_non_empty(entry.get(field))
            keys = normalize_string_list([key_value]) if key_value else []

        reference = compact_search_index_reference(entry)
        for key in keys:
            index.setdefault(key, []).append(reference)

    sorted_keys = sorted_index_keys(index)
    return {
        "metadata": metadata,
        "index": name,
        "field": field,
        "key_count": len(sorted_keys),
        "entry_count": sum(len(values) for values in sorted_keys.values()),
        "keys": sorted_keys,
    }


def build_search_index_payloads(metadata: Dict, certificate_index_payload: Dict) -> Dict[str, Dict]:
    """Build split indexes for common client-side search dimensions."""
    certificates = certificate_index_payload.get("certificates") or []
    definitions = {
        "vendors": "vendor_name",
        "algorithms": "algorithms",
        "statuses": "status",
        "standards": "standard",
    }
    return {
        f"api/indexes/{name}.json": build_search_index_payload(name, field, metadata, certificates)
        for name, field in definitions.items()
    }


def build_examples_payload(metadata: Dict) -> Dict:
    """Build concrete consumer examples for common CMVP API lookups."""
    base = PUBLIC_BASE_URL
    api_base = f"{base}/api"
    return {
        "metadata": metadata,
        "base_url": base,
        "examples": {
            "curl": [
                {
                    "name": "vendor_lookup",
                    "description": "Find certificate references for a vendor from the split vendor index.",
                    "command": f"curl -s {api_base}/indexes/vendors.json | jq '.keys[\"Intel Corporation\"][] | {{certificate_number, module_name, path, status}}'",
                },
                {
                    "name": "module_lookup",
                    "description": "Search module names in the compact certificate index.",
                    "command": f"curl -s {api_base}/certificates/index.json | jq '.certificates[] | select(.module_name | test(\"OpenSSL\"; \"i\")) | {{certificate_number, vendor_name, module_name, path}}'",
                },
                {
                    "name": "algorithm_lookup",
                    "description": "Find certificates whose extracted algorithm categories include AES.",
                    "command": f"curl -s {api_base}/indexes/algorithms.json | jq '.keys.AES[] | {{certificate_number, vendor_name, module_name, path}}'",
                },
                {
                    "name": "status_lookup",
                    "description": "List active certificates from the status index.",
                    "command": f"curl -s {api_base}/indexes/statuses.json | jq '.keys.Active[] | {{certificate_number, vendor_name, module_name, path}}'",
                },
            ],
            "python": [
                {
                    "name": "vendor_modules",
                    "code": (
                        "import requests\n"
                        f"vendor_index = requests.get('{api_base}/indexes/vendors.json', timeout=30).json()\n"
                        "for cert in vendor_index['keys'].get('Intel Corporation', []):\n"
                        "    print(cert['certificate_number'], cert['module_name'], cert['path'])"
                    ),
                },
                {
                    "name": "fetch_certificate_detail",
                    "code": (
                        "import requests\n"
                        f"index = requests.get('{api_base}/certificates/index.json', timeout=30).json()\n"
                        "match = next(cert for cert in index['certificates'] if 'OpenSSL' in (cert.get('module_name') or ''))\n"
                        f"detail = requests.get('{base}' + match['path'], timeout=30).json()\n"
                        "print(detail['certificate']['vendor_name'], detail['certificate']['algorithms'])"
                    ),
                },
            ],
            "javascript": [
                {
                    "name": "algorithm_modules",
                    "code": (
                        f"const res = await fetch('{api_base}/indexes/algorithms.json');\n"
                        "const index = await res.json();\n"
                        "for (const cert of index.keys.AES ?? []) {\n"
                        "  console.log(cert.certificate_number, cert.vendor_name, cert.module_name, cert.path);\n"
                        "}"
                    ),
                },
                {
                    "name": "status_and_standard",
                    "code": (
                        f"const [statuses, standards] = await Promise.all([\n"
                        f"  fetch('{api_base}/indexes/statuses.json').then((r) => r.json()),\n"
                        f"  fetch('{api_base}/indexes/standards.json').then((r) => r.json()),\n"
                        "]);\n"
                        "const active = new Set((statuses.keys.Active ?? []).map((cert) => cert.certificate_number));\n"
                        "const active1403 = (standards.keys['FIPS 140-3'] ?? []).filter((cert) => active.has(cert.certificate_number));\n"
                        "console.log(active1403.slice(0, 10));"
                    ),
                },
            ],
            "agent": [
                {
                    "intent": "Find modules by vendor.",
                    "steps": [
                        "Read api/indexes/vendors.json.",
                        "Select the exact vendor key or case-insensitive nearest key.",
                        "Use each path to fetch api/certificates/{certificate}.json when full detail is needed.",
                    ],
                },
                {
                    "intent": "Find modules by module name.",
                    "steps": [
                        "Read api/certificates/index.json.",
                        "Filter certificates[].module_name client-side.",
                        "Fetch the matched certificate path for vendor contact, validation history, and related files.",
                    ],
                },
                {
                    "intent": "Find modules by algorithm, status, and standard.",
                    "steps": [
                        "Read api/indexes/algorithms.json for the algorithm key.",
                        "Intersect certificate_number values with api/indexes/statuses.json and api/indexes/standards.json as needed.",
                        "Fetch certificate detail paths for final evidence.",
                    ],
                },
            ],
        },
    }


def validate_module_count(modules: List[Dict], label: str, min_expected: int = 100) -> None:
    """
    Validate that the scraped module count is reasonable.

    Prevents silent data loss if NIST changes their HTML structure
    and the scraper returns 0 or very few modules.

    Args:
        modules: List of scraped modules
        label: Description of the module type (for error messages)
        min_expected: Minimum expected count (abort if below this)
    """
    count = len(modules)
    if count < min_expected:
        print(f"FATAL: Only {count} {label} found (expected at least {min_expected}).", file=sys.stderr)
        print("This likely means NIST changed their page structure. Aborting to prevent data loss.", file=sys.stderr)
        sys.exit(1)


def format_count(value: int) -> str:
    """Format integer counts with thousands separators."""
    return f"{value:,}"


def truncate_text(value: Optional[str], limit: int = 160) -> Optional[str]:
    """Trim long free-text fields for documentation examples."""
    if value is None:
        return None
    text = normalize_whitespace(str(value))
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def documentation_paths() -> Dict[str, str]:
    """Return relative documentation paths advertised in the API index."""
    return {
        "homepage": "/",
        "llms_txt": "/llms.txt",
        "llms_full_txt": "/llms-full.txt",
        "api_docs": "/api/docs.md",
        "openapi": "/openapi.json",
        "json_schemas": "/api/schemas/index.schema.json",
    }


def schema_paths(algorithms_summary: Optional[Dict] = None) -> Dict[str, str]:
    """Return published JSON Schema paths."""
    paths = {
        "index": "/api/schemas/index.schema.json",
        "metadata": "/api/schemas/metadata.schema.json",
        "module": "/api/schemas/module.schema.json",
        "module_in_process": "/api/schemas/module-in-process.schema.json",
        "modules": "/api/schemas/modules.schema.json",
        "historical_modules": "/api/schemas/historical-modules.schema.json",
        "modules_in_process": "/api/schemas/modules-in-process.schema.json",
        "certificate_index": "/api/schemas/certificate-index.schema.json",
        "certificate_detail": "/api/schemas/certificate-detail.schema.json",
        "data_quality": "/api/schemas/data-quality.schema.json",
        "examples": "/api/schemas/examples.schema.json",
        "search_index": "/api/schemas/search-index.schema.json",
    }
    if algorithms_summary:
        paths["algorithms"] = "/api/schemas/algorithms.schema.json"
    return paths


def sample_module_example(module: Optional[Dict]) -> Dict:
    """Build a compact module example for generated docs."""
    if not module:
        return {}

    keys = [
        "Certificate Number",
        "Vendor Name",
        "Module Name",
        "Module Type",
        "Validation Date",
        "standard",
        "status",
        "overall_level",
        "sunset_date",
        "algorithms",
        "security_policy_url",
        "certificate_detail_url",
        "detail_available",
        "algorithm_extraction",
    ]
    example = {}
    for key in keys:
        if key not in module:
            continue
        value = module[key]
        if key in {"Module Name"}:
            value = truncate_text(value, 100)
        if key == "algorithm_extraction" and isinstance(value, dict):
            value = dict(value)
            value.pop("attempts", None)
        example[key] = value
    if "description" in module:
        example["description"] = truncate_text(module["description"])
    if "caveat" in module:
        example["caveat"] = truncate_text(module["caveat"])
    return example


def sample_certificate_example(detail: Optional[Dict]) -> Dict:
    """Build a compact certificate detail example for generated docs."""
    if not detail:
        return {}

    vendor = detail.get("vendor") or {}
    example = {
        "certificate_number": detail.get("certificate_number"),
        "dataset": detail.get("dataset"),
        "vendor_name": detail.get("vendor_name"),
        "module_name": truncate_text(detail.get("module_name"), 100),
        "standard": detail.get("standard"),
        "status": detail.get("status"),
        "module_type": detail.get("module_type"),
        "overall_level": detail.get("overall_level"),
        "validation_dates": (detail.get("validation_dates") or [])[:3],
        "sunset_date": detail.get("sunset_date"),
        "caveat": truncate_text(detail.get("caveat")),
        "security_level_exceptions": (detail.get("security_level_exceptions") or [])[:3],
        "vendor": {
            "name": vendor.get("name"),
            "website_url": vendor.get("website_url"),
            "contact_email": vendor.get("contact_email"),
        },
        "related_files": (detail.get("related_files") or [])[:2],
        "validation_history": (detail.get("validation_history") or [])[:2],
        "algorithms": (detail.get("algorithms") or [])[:5],
    }
    if isinstance(detail.get("algorithm_extraction"), dict):
        algorithm_extraction = dict(detail["algorithm_extraction"])
        algorithm_extraction.pop("attempts", None)
        example["algorithm_extraction"] = algorithm_extraction
    return {key: value for key, value in example.items() if value not in (None, [], {})}


def sample_algorithms_example(summary: Optional[Dict]) -> Dict:
    """Build a compact algorithms example for generated docs."""
    if not summary:
        return {}

    algorithms = summary.get("algorithms") or {}
    if not algorithms:
        return {}

    first_name, first_details = next(iter(algorithms.items()))
    return {
        "total_unique_algorithms": summary.get("total_unique_algorithms", 0),
        "total_certificate_algorithm_pairs": summary.get("total_certificate_algorithm_pairs", 0),
        "algorithms": {
            first_name: {
                "count": first_details.get("count", 0),
                "certificates": (first_details.get("certificates") or [])[:5],
            }
        },
    }


def render_json_block(payload: Dict) -> str:
    """Render a JSON code fence for Markdown docs."""
    return "```json\n" + json.dumps(payload, indent=2, ensure_ascii=False) + "\n```"


def build_api_reference_body(
    metadata: Dict,
    sample_module: Optional[Dict],
    sample_certificate_detail: Optional[Dict],
    algorithms_summary: Optional[Dict],
) -> str:
    """
    Build the shared Markdown reference body used by llms-full.txt and api/docs.md.
    """
    total_modules = metadata.get("total_modules", 0)
    total_historical = metadata.get("total_historical_modules", 0)
    total_in_process = metadata.get("total_modules_in_process", 0)
    total_algorithms = metadata.get("total_certificates_with_algorithms", 0)
    total_details = metadata.get("total_certificate_details", 0)
    sample_certificate = (
        (sample_certificate_detail or {}).get("certificate_number")
        or (sample_module or {}).get("Certificate Number")
        or "5238"
    )

    lines = [
        "## Endpoints",
        "",
        "### Index",
        "`GET api/index.json` — API discovery endpoint with resource paths, documentation links, feature flags, and current counts.",
        "",
        "### Metadata",
        "`GET api/metadata.json` — Generation timestamp, source URLs, dataset counts, extraction metrics, and algorithm extraction status.",
        "",
        "### JSON Schemas",
        "`GET api/schemas/index.schema.json` — JSON Schema discovery document for the static API response files.",
        "",
        "### Certificate Index",
        f"`GET api/certificates/index.json` — Compact discovery index for all {format_count(total_details)} per-certificate detail files, including certificate numbers, datasets, paths, vendor/module names, statuses, standards, and algorithm counts.",
        "",
        "### Search Indexes",
        "`GET api/indexes/vendors.json`, `GET api/indexes/algorithms.json`, `GET api/indexes/statuses.json`, and `GET api/indexes/standards.json` — Split lookup files for common client-side search by vendor, algorithm, status, and standard.",
        "",
        "### Data Quality",
        "`GET api/data-quality.json` — Latest run quality report with misses, refreshed records, fallback usage, changed certificates, cache reuse checks, and the next scheduled weekly run.",
        "",
        "### Consumer Examples",
        "`GET api/examples.json` — Copy-ready curl, Python, JavaScript, and agent-oriented query examples for vendor, module, algorithm, status, and standard lookups.",
        "",
        "### Active Modules",
        f"`GET api/modules.json` — All {format_count(total_modules)} active validated modules.",
        "",
        "Example response (truncated):",
        "",
        render_json_block(
            {
                "metadata": {
                    "generated_at": metadata.get("generated_at"),
                    "total_modules": total_modules,
                },
                "modules": [sample_module_example(sample_module)],
            }
        ),
        "",
        "Each active module includes certificate identifiers, vendor/module names, validation metadata, direct Security Policy links, NIST detail URLs, detail availability flags, and algorithm extraction provenance when algorithms were evaluated.",
        "",
        "### Historical Modules",
        f"`GET api/historical-modules.json` — All {format_count(total_historical)} expired or revoked modules for historical lookups.",
        "",
        "### Modules In Process",
        f"`GET api/modules-in-process.json` — All {format_count(total_in_process)} modules currently in the validation pipeline.",
        "",
    ]

    if algorithms_summary:
        lines.extend(
            [
                "### Algorithms",
                f"`GET api/algorithms.json` — Algorithm usage summary across {format_count(total_algorithms)} certificates in the current build.",
                "",
                "`algorithm_extraction` records the configured source, actual source, cache/fallback status, source URL, and extracted row counts for each evaluated certificate.",
                "",
                "Example response (truncated):",
                "",
                render_json_block(sample_algorithms_example(algorithms_summary)),
                "",
            ]
        )

    lines.extend(
        [
            "### Certificate Details",
            f"`GET api/certificates/{{certificate}}.json` — Structured detail record for a specific certificate, including vendor/contact data, related files, validation history, and extracted algorithms when available.",
            "",
            "Example response (truncated):",
            "",
            render_json_block(
                {
                    "metadata": {
                        "generated_at": metadata.get("generated_at"),
                        "dataset": (sample_certificate_detail or {}).get("dataset", "active"),
                        "source": (sample_certificate_detail or {}).get("nist_page_url")
                        or get_certificate_detail_url(int(sample_certificate))
                        if str(sample_certificate).isdigit()
                        else get_certificate_detail_url(5238),
                    },
                    "certificate": sample_certificate_example(sample_certificate_detail),
                }
            ),
            "",
            f"Current build contains {format_count(total_details)} certificate detail records across active and historical datasets.",
            "",
            "## Workflows",
            "",
            "### Discover the API surface",
            "```",
            "GET api/index.json → endpoints, docs links, feature flags, counts",
            "GET api/metadata.json → freshness, scrape provenance, and extraction metrics",
            "GET api/data-quality.json → latest run misses, refreshes, fallbacks, changed certs, and next scheduled run",
            "```",
            "",
            "### Find a module and pull the full certificate record",
            "```",
            "GET api/certificates/index.json → discover every certificate detail path and summary row",
            "GET api/modules.json → locate the certificate number or vendor/module pair",
            f"GET api/certificates/{sample_certificate}.json → full detail record for that certificate",
            "```",
            "",
            "### Check validation status and history for a certificate",
            "```",
            f"GET api/certificates/{sample_certificate}.json → status, sunset_date, validation_history, related_files",
            "```",
            "",
        ]
    )

    if algorithms_summary:
        lines.extend(
            [
                "### Explore algorithm coverage",
                "```",
                "GET api/algorithms.json → counts and certificate lists per algorithm",
                "GET api/indexes/algorithms.json → compact certificate refs keyed by algorithm",
                "GET api/modules.json → filter module rows by algorithms[] entries and inspect algorithm_extraction",
                "```",
                "",
            ]
        )

    lines.extend(
        [
            "## Caveats",
            "",
            f"- **Unofficial:** This project mirrors public CMVP data and is not affiliated with NIST. Use `{OFFICIAL_CMVP_URL}` for authoritative source material.",
            "- **Static JSON:** There is no server-side filtering. Use the split search indexes or download the relevant JSON file and filter client-side.",
            "- **CORS:** GitHub Pages does not send permissive CORS headers. Browser JavaScript on another origin will usually need a proxy.",
            f"- **404s:** Invalid certificate numbers or file paths return GitHub Pages' default 404 page at `{PUBLIC_BASE_URL}`.",
        ]
    )

    if algorithms_summary:
        lines.append(
            f"- **Algorithms coverage:** `api/algorithms.json` summarizes {format_count(total_algorithms)} certificates that had algorithm data in this build. `api/metadata.json` reports extraction cache hits, refreshes, failures, misses, and fallback counts."
        )
    else:
        lines.append(
            "- **Algorithms coverage:** `api/algorithms.json` is only published when algorithm extraction runs for the current build."
        )

    return "\n".join(lines)


def build_llms_txt(metadata: Dict, algorithms_summary: Optional[Dict]) -> str:
    """Build the compact llms.txt discovery file."""
    endpoints = [
        "- `api/index.json` — API discovery endpoint with endpoint and docs links.",
        f"- `api/modules.json` — {format_count(metadata.get('total_modules', 0))} active validated modules.",
        f"- `api/historical-modules.json` — {format_count(metadata.get('total_historical_modules', 0))} historical modules.",
        f"- `api/modules-in-process.json` — {format_count(metadata.get('total_modules_in_process', 0))} modules currently in process.",
        "- `api/metadata.json` — generation timestamp, counts, source URLs, and extraction metrics.",
        f"- `api/certificates/index.json` — compact index for {format_count(metadata.get('total_certificate_details', 0))} certificate detail files.",
        f"- `api/certificates/{{certificate}}.json` — full detail record for a single CMVP certificate.",
        "- `api/indexes/vendors.json`, `api/indexes/algorithms.json`, `api/indexes/statuses.json`, `api/indexes/standards.json` — split search indexes for common filters.",
        "- `api/data-quality.json` — latest run misses, refreshes, fallbacks, changed certs, and weekly run checks.",
        "- `api/examples.json` — curl, Python, JavaScript, and agent-oriented lookup examples.",
    ]
    if algorithms_summary:
        endpoints.append(
            f"- `api/algorithms.json` — algorithm coverage summary across {format_count(metadata.get('total_certificates_with_algorithms', 0))} certificates."
        )

    lines = [
        "# NIST CMVP API",
        "",
        (
            f"> Static JSON API for NIST Cryptographic Module Validation Program data. "
            f"{format_count(metadata.get('total_modules', 0))} active modules, "
            f"{format_count(metadata.get('total_historical_modules', 0))} historical modules, "
            f"{format_count(metadata.get('total_modules_in_process', 0))} modules in process, and "
            f"{format_count(metadata.get('total_certificate_details', 0))} certificate detail records. No auth required."
        ),
        "",
        f"Base URL: {PUBLIC_BASE_URL}/",
        "",
        "All data is static JSON. Append paths to the base URL.",
        "",
        *endpoints,
        "",
        "## Documentation",
        "",
        "- [API Reference](api/docs.md): endpoint reference with examples and workflows.",
        "- [Complete Documentation](llms-full.txt): fuller single-file agent reference.",
        "- [OpenAPI](openapi.json): OpenAPI 3.0.3 schema for the JSON endpoints.",
        "- [JSON Schemas](api/schemas/index.schema.json): JSON Schema index for static API responses.",
        "",
        "## Caveats",
        "",
        f"- Unofficial mirror of public CMVP data. Use {OFFICIAL_CMVP_URL} for authoritative source material.",
        "- Static JSON only. Filter client-side after downloading the relevant resource.",
        "- Browser JavaScript on another origin may need a proxy because GitHub Pages does not send permissive CORS headers.",
    ]

    if algorithms_summary:
        lines.append(
            f"- `api/algorithms.json` covers {format_count(metadata.get('total_certificates_with_algorithms', 0))} certificates in the current build."
        )
    else:
        lines.append("- `api/algorithms.json` is only published when algorithm extraction runs for the current build.")

    return "\n".join(lines)


def build_llms_full_txt(
    metadata: Dict,
    sample_module: Optional[Dict],
    sample_certificate_detail: Optional[Dict],
    algorithms_summary: Optional[Dict],
) -> str:
    """Build the full llms reference file."""
    api_ref_body = build_api_reference_body(
        metadata,
        sample_module,
        sample_certificate_detail,
        algorithms_summary,
    )
    return "\n".join(
        [
            "# NIST CMVP API",
            "",
            (
                f"> Static JSON API for NIST Cryptographic Module Validation Program data. "
                f"Auto-updated weekly from the public CMVP site. "
                f"{format_count(metadata.get('total_modules', 0))} active modules, "
                f"{format_count(metadata.get('total_historical_modules', 0))} historical modules, "
                f"{format_count(metadata.get('total_modules_in_process', 0))} modules in process, and "
                f"{format_count(metadata.get('total_certificate_details', 0))} certificate detail records."
            ),
            "",
            f"Base URL: {PUBLIC_BASE_URL}/",
            "",
            api_ref_body,
        ]
    )


def build_api_docs_markdown(
    metadata: Dict,
    sample_module: Optional[Dict],
    sample_certificate_detail: Optional[Dict],
    algorithms_summary: Optional[Dict],
) -> str:
    """Build the human-readable Markdown API reference."""
    api_ref_body = build_api_reference_body(
        metadata,
        sample_module,
        sample_certificate_detail,
        algorithms_summary,
    )
    intro_lines = [
        "# NIST CMVP API Reference",
        "",
        "Static JSON API for NIST Cryptographic Module Validation Program data.",
        "",
        f"- **{format_count(metadata.get('total_modules', 0))}** active validated modules",
        f"- **{format_count(metadata.get('total_historical_modules', 0))}** historical modules",
        f"- **{format_count(metadata.get('total_modules_in_process', 0))}** modules in process",
        f"- **{format_count(metadata.get('total_certificate_details', 0))}** certificate detail records",
    ]
    if algorithms_summary:
        intro_lines.append(
            f"- **{format_count(metadata.get('total_certificates_with_algorithms', 0))}** certificates with algorithm summaries"
        )
    intro_lines.extend(
        [
            "- No auth required, unofficial project, GitHub Pages hosted.",
            "",
            f"Base URL: `{PUBLIC_BASE_URL}/`",
            "",
            api_ref_body,
        ]
    )
    return "\n".join(intro_lines)


def build_index_html(metadata: Dict, algorithms_summary: Optional[Dict]) -> str:
    """Build the basic SCF-style landing page for the published site."""
    total_modules = format_count(metadata.get("total_modules", 0))
    total_historical = format_count(metadata.get("total_historical_modules", 0))
    total_in_process = format_count(metadata.get("total_modules_in_process", 0))
    total_details = format_count(metadata.get("total_certificate_details", 0))
    updated_at = metadata.get("generated_at", "")

    agents_links = [
        '    <li><a href="llms.txt">llms.txt</a></li>',
        '    <li><a href="llms-full.txt">llms-full.txt</a></li>',
        '    <li><a href="api/docs.md">api/docs.md</a></li>',
        '    <li><a href="openapi.json">openapi.json</a></li>',
        '    <li><a href="api/schemas/index.schema.json">JSON Schemas</a></li>',
        '    <li><a href="api/examples.json">examples.json</a></li>',
    ]

    endpoint_links = [
        '    <li><a href="api/index.json"><code>index</code></a></li>',
        '    <li><a href="api/metadata.json"><code>metadata</code></a></li>',
        '    <li><a href="api/data-quality.json"><code>data-quality</code></a></li>',
        '    <li><a href="api/modules.json"><code>modules</code></a></li>',
        '    <li><a href="api/certificates/index.json"><code>certificates/index</code></a> &middot; <a href="api/certificates/5238.json"><code>certificates/{certificate}</code></a></li>',
        '    <li><a href="api/indexes/vendors.json"><code>indexes/vendors</code></a> &middot; <a href="api/indexes/algorithms.json"><code>indexes/algorithms</code></a> &middot; <a href="api/indexes/statuses.json"><code>indexes/statuses</code></a> &middot; <a href="api/indexes/standards.json"><code>indexes/standards</code></a></li>',
        '    <li><a href="api/historical-modules.json"><code>historical-modules</code></a></li>',
        '    <li><a href="api/modules-in-process.json"><code>modules-in-process</code></a></li>',
    ]
    if algorithms_summary:
        endpoint_links.append('    <li><a href="api/algorithms.json"><code>algorithms</code></a></li>')

    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8" />',
            '  <meta name="viewport" content="width=device-width, initial-scale=1" />',
            "  <title>CMVP API</title>",
            (
                '  <meta name="description" content="Static JSON API for NIST CMVP data. '
                f'{total_modules} active modules, {total_historical} historical modules, '
                f'{total_in_process} modules in process." />'
            ),
            "  <style>",
            "    body { font-family: system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; max-width: 600px; margin: 0 auto; padding: 2rem 1rem; line-height: 1.6; }",
            "    h1 { color: #cdd6f4; font-size: 1.3rem; margin-bottom: 0.5rem; }",
            "    h2 { color: #a6adc8; font-size: 0.9rem; margin-top: 1.5rem; margin-bottom: 0.5rem; }",
            "    p { color: #a6adc8; margin-bottom: 0.75rem; font-size: 0.9rem; }",
            "    a { color: #89b4fa; }",
            "    a:hover { color: #b4befe; }",
            "    code { color: #a6e3a1; font-size: 0.85em; }",
            "    ul { padding-left: 1.2rem; margin: 0; }",
            "    li { margin-bottom: 0.25rem; font-size: 0.9rem; }",
            "    .sub { color: #6c7086; font-size: 0.8rem; margin-top: 2rem; }",
            "    .sub a { color: #6c7086; }",
            "    .sub a:hover { color: #89b4fa; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>CMVP API</h1>",
            (
                f'  <p>{total_modules} active modules, {total_historical} historical modules, '
                f'{total_in_process} modules in process, and {total_details} certificate detail records. '
                f'Static JSON from the <a href="{OFFICIAL_CMVP_URL}">NIST Cryptographic Module Validation Program</a>.</p>'
            ),
            "  <p>Unofficial mirror. No auth required. Updated weekly.</p>",
            "",
            "  <h2>Agents</h2>",
            "  <ul>",
            *agents_links,
            "  </ul>",
            "",
            "  <h2>Endpoints</h2>",
            "  <ul>",
            *endpoint_links,
            "  </ul>",
            "",
            f'  <p class="sub">Updated {updated_at} &middot; Unofficial CMVP mirror &middot; <a href="{REPO_URL}">hackIDLE</a></p>',
            "</body>",
            "</html>",
        ]
    )


def generate_text_artifacts(
    metadata: Dict,
    sample_module: Optional[Dict],
    sample_certificate_detail: Optional[Dict],
    algorithms_summary: Optional[Dict],
) -> Dict[str, str]:
    """Generate all tracked text artifacts for the published site."""
    return {
        "llms.txt": build_llms_txt(metadata, algorithms_summary),
        "llms-full.txt": build_llms_full_txt(
            metadata,
            sample_module,
            sample_certificate_detail,
            algorithms_summary,
        ),
        "api/docs.md": build_api_docs_markdown(
            metadata,
            sample_module,
            sample_certificate_detail,
            algorithms_summary,
        ),
        "index.html": build_index_html(metadata, algorithms_summary),
    }


def json_schema_document(title: str, schema_id: str, schema: Dict) -> Dict:
    """Wrap a JSON Schema body with common metadata."""
    document = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{PUBLIC_BASE_URL}{schema_id}",
        "title": title,
    }
    document.update(schema)
    return document


def algorithm_extraction_schema() -> Dict:
    """Return the shared algorithm extraction provenance schema."""
    return {
        "type": "object",
        "additionalProperties": True,
        "required": [
            "schema_version",
            "status",
            "configured_source",
            "source",
            "cached",
            "fallback_used",
            "cache_version",
            "algorithm_count",
            "detailed_algorithm_count",
        ],
        "properties": {
            "schema_version": {"type": "string"},
            "status": {"type": "string", "enum": ["parsed", "cached", "miss", "skipped"]},
            "configured_source": {"type": "string"},
            "source": {"type": "string"},
            "source_url": {"type": ["string", "null"], "format": "uri"},
            "cached": {"type": "boolean"},
            "fallback_used": {"type": "boolean"},
            "cache_version": {"type": "string"},
            "algorithm_count": {"type": "integer", "minimum": 0},
            "detailed_algorithm_count": {"type": "integer", "minimum": 0},
            "attempts": {
                "type": "array",
                "items": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
    }


def module_schema() -> Dict:
    """Return a backwards-compatible schema for active and historical module rows."""
    return {
        "type": "object",
        "additionalProperties": True,
        "required": [
            "Certificate Number",
            "Vendor Name",
            "Module Name",
            "security_policy_url",
            "certificate_detail_url",
            "detail_available",
        ],
        "properties": {
            "Certificate Number": {"type": "string", "pattern": "^[0-9]+$"},
            "Certificate Number_url": {"type": "string"},
            "Vendor Name": {"type": "string"},
            "Module Name": {"type": "string"},
            "Module Type": {"type": "string"},
            "Validation Date": {"type": "string"},
            "Status": {"type": "string"},
            "security_policy_url": {"type": "string", "format": "uri"},
            "certificate_detail_url": {"type": "string", "format": "uri"},
            "standard": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "overall_level": {"type": ["integer", "string", "null"]},
            "sunset_date": {"type": ["string", "null"]},
            "detail_available": {"type": "boolean"},
            "algorithms": {"type": "array", "items": {"type": "string"}},
            "algorithms_detailed": {"type": "array", "items": {"type": "string"}},
            "algorithm_extraction": algorithm_extraction_schema(),
        },
    }


def module_in_process_schema() -> Dict:
    """Return the schema for CMVP modules in process rows."""
    return {
        "type": "object",
        "additionalProperties": True,
        "required": ["Module Name", "Vendor Name", "Standard", "Status"],
        "properties": {
            "Module Name": {"type": "string"},
            "Vendor Name": {"type": "string"},
            "Vendor Name_url": {"type": "string"},
            "Standard": {"type": "string"},
            "Status": {"type": "string"},
        },
    }


def metadata_schema() -> Dict:
    """Return the dataset metadata schema."""
    return {
        "type": "object",
        "additionalProperties": True,
        "required": [
            "generated_at",
            "total_modules",
            "total_historical_modules",
            "total_modules_in_process",
            "total_certificates_with_algorithms",
            "total_certificate_details",
            "source",
            "modules_in_process_source",
            "algorithm_source",
            "algorithm_cache_version",
            "version",
        ],
        "properties": {
            "generated_at": {"type": "string", "format": "date-time"},
            "total_modules": {"type": "integer", "minimum": 0},
            "total_historical_modules": {"type": "integer", "minimum": 0},
            "total_modules_in_process": {"type": "integer", "minimum": 0},
            "total_certificates_with_algorithms": {"type": "integer", "minimum": 0},
            "total_certificate_details": {"type": "integer", "minimum": 0},
            "source": {"type": "string", "format": "uri"},
            "modules_in_process_source": {"type": "string", "format": "uri"},
            "algorithm_source": {"type": "string"},
            "algorithm_cache_version": {"type": "string"},
            "algorithm_extraction_schema_version": {"type": "string"},
            "extraction_metrics": {"type": "object", "additionalProperties": True},
            "version": {"type": "string"},
        },
    }


def response_schema(metadata_ref: str, array_name: str, item_ref: str) -> Dict:
    """Return a two-field metadata/list response schema."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["metadata", array_name],
        "properties": {
            "metadata": {"$ref": metadata_ref},
            array_name: {"type": "array", "items": {"$ref": item_ref}},
        },
    }


def certificate_detail_schema() -> Dict:
    """Return the per-certificate detail response schema."""
    certificate_schema = {
        "type": "object",
        "additionalProperties": True,
        "required": [
            "certificate_number",
            "dataset",
            "generated_at",
            "nist_page_url",
            "certificate_detail_url",
            "security_policy_url",
            "vendor_name",
            "module_name",
            "standard",
            "status",
            "related_files",
            "validation_history",
            "vendor",
        ],
        "properties": {
            "certificate_number": {"type": "string", "pattern": "^[0-9]+$"},
            "dataset": {"type": "string", "enum": ["active", "historical"]},
            "generated_at": {"type": "string", "format": "date-time"},
            "nist_page_url": {"type": "string", "format": "uri"},
            "certificate_detail_url": {"type": "string", "format": "uri"},
            "security_policy_url": {"type": ["string", "null"], "format": "uri"},
            "vendor_name": {"type": ["string", "null"]},
            "module_name": {"type": ["string", "null"]},
            "standard": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "related_files": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
            "validation_history": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
            "vendor": {"type": "object", "additionalProperties": True},
            "algorithms": {"type": "array", "items": {"type": "string"}},
            "algorithms_detailed": {"type": "array", "items": {"type": "string"}},
            "algorithm_extraction": algorithm_extraction_schema(),
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["metadata", "certificate"],
        "properties": {
            "metadata": {
                "type": "object",
                "additionalProperties": True,
                "required": ["generated_at", "dataset", "source"],
            },
            "certificate": certificate_schema,
        },
    }


def certificate_index_schema() -> Dict:
    """Return the certificate discovery index response schema."""
    entry_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "certificate_number",
            "dataset",
            "path",
            "nist_page_url",
            "certificate_detail_url",
            "security_policy_url",
            "vendor_name",
            "module_name",
            "standard",
            "status",
            "module_type",
            "overall_level",
            "validation_date",
            "validation_dates",
            "sunset_date",
            "algorithms",
            "algorithm_count",
            "algorithm_extraction_status",
            "algorithm_source",
            "detail_available",
        ],
        "properties": {
            "certificate_number": {"type": "string", "pattern": "^[0-9]+$"},
            "dataset": {"type": "string", "enum": ["active", "historical"]},
            "path": {"type": "string", "pattern": "^/api/certificates/[0-9]+\\.json$"},
            "nist_page_url": {"type": "string", "format": "uri"},
            "certificate_detail_url": {"type": "string", "format": "uri"},
            "security_policy_url": {"type": ["string", "null"], "format": "uri"},
            "vendor_name": {"type": ["string", "null"]},
            "module_name": {"type": ["string", "null"]},
            "standard": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "module_type": {"type": ["string", "null"]},
            "overall_level": {"type": ["integer", "string", "null"]},
            "validation_date": {"type": ["string", "null"]},
            "validation_dates": {"type": "array", "items": {"type": "string"}},
            "sunset_date": {"type": ["string", "null"]},
            "algorithms": {"type": "array", "items": {"type": "string"}},
            "algorithm_count": {"type": "integer", "minimum": 0},
            "algorithm_extraction_status": {"type": ["string", "null"]},
            "algorithm_source": {"type": ["string", "null"]},
            "detail_available": {"type": "boolean"},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["metadata", "total_certificates", "certificate_paths", "certificates"],
        "properties": {
            "metadata": {"$ref": "/api/schemas/metadata.schema.json"},
            "total_certificates": {"type": "integer", "minimum": 0},
            "certificate_paths": {
                "type": "object",
                "additionalProperties": {
                    "type": "string",
                    "pattern": "^/api/certificates/[0-9]+\\.json$",
                },
            },
            "certificates": {"type": "array", "items": entry_schema},
        },
    }


def algorithms_schema() -> Dict:
    """Return the algorithms summary response schema."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["total_unique_algorithms", "total_certificate_algorithm_pairs", "algorithms", "metadata"],
        "properties": {
            "total_unique_algorithms": {"type": "integer", "minimum": 0},
            "total_certificate_algorithm_pairs": {"type": "integer", "minimum": 0},
            "algorithms": {
                "type": "object",
                "additionalProperties": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["count", "certificates"],
                    "properties": {
                        "count": {"type": "integer", "minimum": 0},
                        "certificates": {"type": "array", "items": {"type": "integer"}},
                    },
                },
            },
            "metadata": {"type": "object", "additionalProperties": True},
        },
    }


def data_quality_schema() -> Dict:
    """Return the data quality report response schema."""
    quality_record_schema = {
        "type": "object",
        "additionalProperties": True,
        "required": ["certificate_number", "dataset", "path", "reason"],
        "properties": {
            "certificate_number": {"type": ["string", "null"]},
            "dataset": {"type": "string", "enum": ["active", "historical"]},
            "path": {"type": ["string", "null"]},
            "vendor_name": {"type": ["string", "null"]},
            "module_name": {"type": ["string", "null"]},
            "standard": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "reason": {"type": "string"},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "metadata",
            "summary",
            "update_monitor",
            "misses",
            "refreshed_records",
            "fallback_usage",
            "changed_certificates",
        ],
        "properties": {
            "metadata": {"$ref": "/api/schemas/metadata.schema.json"},
            "summary": {
                "type": "object",
                "additionalProperties": {"type": "integer", "minimum": 0},
            },
            "update_monitor": {
                "type": "object",
                "additionalProperties": True,
                "required": ["status", "schedule", "latest_run_generated_at", "next_scheduled_run", "checks"],
                "properties": {
                    "status": {"type": "string", "enum": ["pass", "warn"]},
                    "schedule": {"type": "string"},
                    "schedule_description": {"type": "string"},
                    "latest_run_generated_at": {"type": "string"},
                    "next_scheduled_run": {"type": ["string", "null"]},
                    "latest_run_metrics": {"type": "object", "additionalProperties": True},
                    "checks": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                },
            },
            "misses": {"type": "array", "items": quality_record_schema},
            "refreshed_records": {"type": "array", "items": quality_record_schema},
            "fallback_usage": {"type": "array", "items": quality_record_schema},
            "changed_certificates": {"type": "array", "items": quality_record_schema},
        },
    }


def examples_schema() -> Dict:
    """Return the consumer examples response schema."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["metadata", "base_url", "examples"],
        "properties": {
            "metadata": {"$ref": "/api/schemas/metadata.schema.json"},
            "base_url": {"type": "string", "format": "uri"},
            "examples": {
                "type": "object",
                "additionalProperties": True,
                "required": ["curl", "python", "javascript", "agent"],
                "properties": {
                    "curl": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "python": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "javascript": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "agent": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                },
            },
        },
    }


def search_index_schema() -> Dict:
    """Return the shared split search-index response schema."""
    reference_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "certificate_number",
            "dataset",
            "path",
            "vendor_name",
            "module_name",
            "standard",
            "status",
            "algorithm_count",
        ],
        "properties": {
            "certificate_number": {"type": "string", "pattern": "^[0-9]+$"},
            "dataset": {"type": "string", "enum": ["active", "historical"]},
            "path": {"type": "string", "pattern": "^/api/certificates/[0-9]+\\.json$"},
            "vendor_name": {"type": ["string", "null"]},
            "module_name": {"type": ["string", "null"]},
            "standard": {"type": ["string", "null"]},
            "status": {"type": ["string", "null"]},
            "algorithm_count": {"type": "integer", "minimum": 0},
        },
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["metadata", "index", "field", "key_count", "entry_count", "keys"],
        "properties": {
            "metadata": {"$ref": "/api/schemas/metadata.schema.json"},
            "index": {"type": "string", "enum": ["vendors", "algorithms", "statuses", "standards"]},
            "field": {"type": "string"},
            "key_count": {"type": "integer", "minimum": 0},
            "entry_count": {"type": "integer", "minimum": 0},
            "keys": {
                "type": "object",
                "additionalProperties": {"type": "array", "items": reference_schema},
            },
        },
    }


def build_schema_index_payload(algorithms_summary: Optional[Dict]) -> Dict:
    """Build the JSON Schema discovery document."""
    return {
        "name": "NIST CMVP API JSON Schemas",
        "schema_version": "1.0",
        "base_url": PUBLIC_BASE_URL,
        "schemas": schema_paths(algorithms_summary),
    }


def generate_json_schema_artifacts(algorithms_summary: Optional[Dict]) -> Dict[str, Dict]:
    """Generate tracked JSON Schema artifacts for API response files."""
    metadata_path = "/api/schemas/metadata.schema.json"
    module_path = "/api/schemas/module.schema.json"
    module_in_process_path = "/api/schemas/module-in-process.schema.json"
    paths = schema_paths(algorithms_summary)
    artifacts = {
        "api/schemas/index.schema.json": json_schema_document(
            "NIST CMVP API JSON Schema Index",
            paths["index"],
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "schema_version", "base_url", "schemas"],
                "properties": {
                    "name": {"type": "string"},
                    "schema_version": {"type": "string"},
                    "base_url": {"type": "string", "format": "uri"},
                    "schemas": {"type": "object", "additionalProperties": {"type": "string"}},
                },
                "examples": [build_schema_index_payload(algorithms_summary)],
            },
        ),
        "api/schemas/metadata.schema.json": json_schema_document(
            "NIST CMVP API Metadata",
            paths["metadata"],
            metadata_schema(),
        ),
        "api/schemas/module.schema.json": json_schema_document(
            "NIST CMVP Module Row",
            module_path,
            module_schema(),
        ),
        "api/schemas/module-in-process.schema.json": json_schema_document(
            "NIST CMVP Module In Process Row",
            module_in_process_path,
            module_in_process_schema(),
        ),
        "api/schemas/modules.schema.json": json_schema_document(
            "NIST CMVP Active Modules Response",
            paths["modules"],
            response_schema(metadata_path, "modules", module_path),
        ),
        "api/schemas/historical-modules.schema.json": json_schema_document(
            "NIST CMVP Historical Modules Response",
            paths["historical_modules"],
            response_schema(metadata_path, "modules", module_path),
        ),
        "api/schemas/modules-in-process.schema.json": json_schema_document(
            "NIST CMVP Modules In Process Response",
            paths["modules_in_process"],
            response_schema(metadata_path, "modules_in_process", module_in_process_path),
        ),
        "api/schemas/certificate-index.schema.json": json_schema_document(
            "NIST CMVP Certificate Index Response",
            paths["certificate_index"],
            certificate_index_schema(),
        ),
        "api/schemas/certificate-detail.schema.json": json_schema_document(
            "NIST CMVP Certificate Detail Response",
            paths["certificate_detail"],
            certificate_detail_schema(),
        ),
        "api/schemas/data-quality.schema.json": json_schema_document(
            "NIST CMVP Data Quality Report",
            paths["data_quality"],
            data_quality_schema(),
        ),
        "api/schemas/examples.schema.json": json_schema_document(
            "NIST CMVP Consumer Examples",
            paths["examples"],
            examples_schema(),
        ),
        "api/schemas/search-index.schema.json": json_schema_document(
            "NIST CMVP Split Search Index",
            paths["search_index"],
            search_index_schema(),
        ),
    }
    if algorithms_summary:
        artifacts["api/schemas/algorithms.schema.json"] = json_schema_document(
            "NIST CMVP Algorithms Summary Response",
            paths["algorithms"],
            algorithms_schema(),
        )
    return artifacts


def build_index_payload(metadata: Dict, algorithms_summary: Optional[Dict]) -> Dict:
    """Build the API index payload published at api/index.json."""
    endpoints = {
        "index": "/api/index.json",
        "modules": "/api/modules.json",
        "historical_modules": "/api/historical-modules.json",
        "modules_in_process": "/api/modules-in-process.json",
        "metadata": "/api/metadata.json",
        "certificate_index": "/api/certificates/index.json",
        "certificate_detail_template": "/api/certificates/{certificate}.json",
        "data_quality": "/api/data-quality.json",
        "examples": "/api/examples.json",
        "vendor_index": "/api/indexes/vendors.json",
        "algorithm_index": "/api/indexes/algorithms.json",
        "status_index": "/api/indexes/statuses.json",
        "standard_index": "/api/indexes/standards.json",
    }
    if algorithms_summary:
        endpoints["algorithms"] = "/api/algorithms.json"

    return {
        "name": "NIST CMVP API",
        "description": "Static JSON API for NIST Cryptographic Module Validation Program data with certificate detail records and generated agent-facing documentation",
        "base_url": PUBLIC_BASE_URL,
        "endpoints": endpoints,
        "documentation": documentation_paths(),
        "schemas": schema_paths(algorithms_summary),
        "last_updated": metadata.get("generated_at"),
        "total_modules": metadata.get("total_modules", 0),
        "total_historical_modules": metadata.get("total_historical_modules", 0),
        "total_modules_in_process": metadata.get("total_modules_in_process", 0),
        "total_certificates_with_algorithms": metadata.get("total_certificates_with_algorithms", 0),
        "total_certificate_details": metadata.get("total_certificate_details", 0),
        "features": {
            "security_policy_urls": True,
            "certificate_detail_urls": True,
            "algorithm_extraction": bool(algorithms_summary),
            "algorithm_extraction_provenance": True,
            "extraction_metrics": True,
            "data_quality_report": True,
            "consumer_examples": True,
            "search_indexes": True,
            "certificate_index": True,
            "certificate_detail_records": True,
            "llms_txt": True,
            "llms_full_txt": True,
            "markdown_api_docs": True,
            "openapi_spec": True,
            "json_schemas": True,
        },
    }


def infer_openapi_schema(value) -> Dict:
    """Infer a simple OpenAPI schema fragment from an example value."""
    if isinstance(value, bool):
        return {"type": "boolean", "example": value}
    if isinstance(value, int):
        return {"type": "integer", "example": value}
    if isinstance(value, float):
        return {"type": "number", "example": value}
    if isinstance(value, list):
        item_example = value[0] if value else ""
        if isinstance(item_example, dict):
            return {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": True,
                },
            }
        if isinstance(item_example, bool):
            return {"type": "array", "items": {"type": "boolean"}, "example": value[:3]}
        if isinstance(item_example, int):
            return {"type": "array", "items": {"type": "integer"}, "example": value[:3]}
        return {"type": "array", "items": {"type": "string"}, "example": value[:3]}
    if isinstance(value, dict):
        return {"type": "object", "additionalProperties": True}
    if value is None:
        return {"type": "string", "nullable": True, "example": ""}
    return {"type": "string", "example": str(value)}


def generate_openapi_spec(
    modules: List[Dict],
    metadata: Dict,
    sample_certificate_detail: Optional[Dict] = None,
    algorithms_summary: Optional[Dict] = None,
) -> Dict:
    """
    Generate an OpenAPI 3.0.3 spec from the actual scraped data schema.

    Uses the first module as an example and derives field types from real data,
    ensuring the spec always matches the actual API output.

    Args:
        modules: List of scraped module dictionaries
        metadata: The metadata dictionary

    Returns:
        OpenAPI spec as a dictionary
    """
    algorithms_available = bool(algorithms_summary)

    # Build module schema properties from actual field names and known optional
    # detail fields that may be absent from the first sampled record.
    sample = modules[0] if modules else {}
    module_properties = {}
    module_schema_values = dict(sample)
    for key in MODULE_DETAIL_FIELDS:
        module_schema_values.setdefault(key, None)
    for key, value in module_schema_values.items():
        module_properties[key] = infer_openapi_schema(value)

    detail_properties = {}
    detail_schema_values = dict(sample_certificate_detail or {})
    for key in MODULE_DETAIL_FIELDS:
        detail_schema_values.setdefault(key, None)
    for key, value in detail_schema_values.items():
        detail_properties[key] = infer_openapi_schema(value)

    index_payload = build_index_payload(metadata, algorithms_summary)

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "NIST CMVP Data API",
            "description": (
                "Static JSON API for NIST Cryptographic Module Validation Program data. "
                "Auto-updated weekly via GitHub Actions. "
                f"Unofficial project - see {OFFICIAL_CMVP_URL} for authoritative data."
            ),
            "version": metadata.get("version", "2.0"),
            "contact": {
                "url": REPO_URL
            }
        },
        "externalDocs": {
            "description": "Markdown API reference",
            "url": f"{PUBLIC_BASE_URL}/api/docs.md",
        },
        "servers": [
            {
                "url": PUBLIC_BASE_URL,
                "description": "GitHub Pages (production)"
            }
        ],
        "paths": {
            "/api/index.json": {
                "get": {
                    "summary": "API index and endpoint listing",
                    "operationId": "getIndex",
                    "responses": {
                        "200": {
                            "description": "API discovery endpoint with available endpoints and feature flags",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Index"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/metadata.json": {
                "get": {
                    "summary": "Dataset metadata",
                    "operationId": "getMetadata",
                    "responses": {
                        "200": {
                            "description": "Generation timestamp, module counts, and data source information",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Metadata"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/data-quality.json": {
                "get": {
                    "summary": "Latest data quality report",
                    "operationId": "getDataQuality",
                    "responses": {
                        "200": {
                            "description": "Misses, refreshed records, fallback usage, changed certificates, and run-health checks",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/DataQualityReport"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/examples.json": {
                "get": {
                    "summary": "Consumer examples",
                    "operationId": "getExamples",
                    "responses": {
                        "200": {
                            "description": "curl, Python, JavaScript, and agent-oriented examples for common queries",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ExamplesResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/indexes/vendors.json": {
                "get": {
                    "summary": "Vendor search index",
                    "operationId": "getVendorIndex",
                    "responses": {
                        "200": {
                            "description": "Certificate references keyed by vendor name",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SearchIndexResponse"}}},
                        }
                    },
                }
            },
            "/api/indexes/algorithms.json": {
                "get": {
                    "summary": "Algorithm search index",
                    "operationId": "getAlgorithmIndex",
                    "responses": {
                        "200": {
                            "description": "Certificate references keyed by algorithm category",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SearchIndexResponse"}}},
                        }
                    },
                }
            },
            "/api/indexes/statuses.json": {
                "get": {
                    "summary": "Status search index",
                    "operationId": "getStatusIndex",
                    "responses": {
                        "200": {
                            "description": "Certificate references keyed by validation status",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SearchIndexResponse"}}},
                        }
                    },
                }
            },
            "/api/indexes/standards.json": {
                "get": {
                    "summary": "Standard search index",
                    "operationId": "getStandardIndex",
                    "responses": {
                        "200": {
                            "description": "Certificate references keyed by FIPS standard",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/SearchIndexResponse"}}},
                        }
                    },
                }
            },
            "/api/modules.json": {
                "get": {
                    "summary": "Active validated cryptographic modules",
                    "operationId": "getModules",
                    "responses": {
                        "200": {
                            "description": f"Currently {metadata.get('total_modules', 0)} active validated modules with enriched details",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ModulesResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/historical-modules.json": {
                "get": {
                    "summary": "Historical (expired/revoked) cryptographic modules",
                    "operationId": "getHistoricalModules",
                    "responses": {
                        "200": {
                            "description": f"Currently {metadata.get('total_historical_modules', 0)} historical modules",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ModulesResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/modules-in-process.json": {
                "get": {
                    "summary": "Modules currently in the validation process",
                    "operationId": "getModulesInProcess",
                    "responses": {
                        "200": {
                            "description": f"Currently {metadata.get('total_modules_in_process', 0)} modules in process",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ModulesInProcessResponse"}
                                }
                            }
                        }
                    }
                }
            },
            **(
                {
                    "/api/algorithms.json": {
                        "get": {
                            "summary": "Algorithm usage statistics across all certificates",
                            "operationId": "getAlgorithms",
                            "responses": {
                                "200": {
                                    "description": "Algorithm counts and certificate mappings",
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": "#/components/schemas/AlgorithmsResponse"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if algorithms_available
                else {}
            ),
            "/api/certificates/index.json": {
                "get": {
                    "summary": "Certificate detail discovery index",
                    "operationId": "getCertificateIndex",
                    "responses": {
                        "200": {
                            "description": "Compact index of all per-certificate JSON detail files",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CertificateIndexResponse"}
                                }
                            }
                        }
                    }
                }
            },
            "/api/certificates/{certificate}.json": {
                "get": {
                    "summary": "Full certificate detail record",
                    "operationId": "getCertificateDetail",
                    "parameters": [
                        {
                            "name": "certificate",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                            "description": "Numeric CMVP certificate number"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Certificate detail payload mirroring the NIST certificate page sections",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CertificateDetailResponse"}
                                }
                            }
                        },
                        "404": {
                            "description": "Certificate detail record not found"
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                "Metadata": {
                    "type": "object",
                    "properties": {
                        "generated_at": {"type": "string", "format": "date-time", "example": metadata.get("generated_at", "")},
                        "total_modules": {"type": "integer", "example": metadata.get("total_modules", 0)},
                        "total_historical_modules": {"type": "integer", "example": metadata.get("total_historical_modules", 0)},
                        "total_modules_in_process": {"type": "integer", "example": metadata.get("total_modules_in_process", 0)},
                        "total_certificates_with_algorithms": {"type": "integer", "example": metadata.get("total_certificates_with_algorithms", 0)},
                        "total_certificate_details": {"type": "integer", "example": metadata.get("total_certificate_details", 0)},
                        "source": {"type": "string", "example": metadata.get("source", "")},
                        "modules_in_process_source": {"type": "string", "example": metadata.get("modules_in_process_source", "")},
                        "algorithm_source": {"type": "string", "example": metadata.get("algorithm_source", "")},
                        "algorithm_cache_version": {"type": "string", "example": metadata.get("algorithm_cache_version", "")},
                        "algorithm_extraction_schema_version": {"type": "string", "example": metadata.get("algorithm_extraction_schema_version", "")},
                        "extraction_metrics": {"type": "object", "additionalProperties": True},
                        "version": {"type": "string", "example": metadata.get("version", "")}
                    }
                },
                "Module": {
                    "type": "object",
                    "description": "A FIPS 140-2/140-3 validated cryptographic module",
                    "properties": module_properties
                },
                "ModulesResponse": {
                    "type": "object",
                    "properties": {
                        "metadata": {"$ref": "#/components/schemas/Metadata"},
                        "modules": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Module"}
                        }
                    }
                },
                "ModulesInProcessResponse": {
                    "type": "object",
                    "properties": {
                        "metadata": {"$ref": "#/components/schemas/Metadata"},
                        "modules_in_process": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Module"}
                        }
                    }
                },
                "DataQualityReport": {
                    "type": "object",
                    "properties": {
                        "metadata": {"$ref": "#/components/schemas/Metadata"},
                        "summary": {"type": "object", "additionalProperties": {"type": "integer"}},
                        "update_monitor": {"type": "object", "additionalProperties": True},
                        "misses": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                        "refreshed_records": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                        "fallback_usage": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                        "changed_certificates": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    },
                },
                "ExamplesResponse": {
                    "type": "object",
                    "properties": {
                        "metadata": {"$ref": "#/components/schemas/Metadata"},
                        "base_url": {"type": "string"},
                        "examples": {"type": "object", "additionalProperties": True},
                    },
                },
                "SearchIndexReference": {
                    "type": "object",
                    "properties": {
                        "certificate_number": {"type": "string"},
                        "dataset": {"type": "string", "enum": ["active", "historical"]},
                        "path": {"type": "string", "example": "/api/certificates/5238.json"},
                        "vendor_name": {"type": "string", "nullable": True},
                        "module_name": {"type": "string", "nullable": True},
                        "standard": {"type": "string", "nullable": True},
                        "status": {"type": "string", "nullable": True},
                        "algorithm_count": {"type": "integer"},
                    },
                },
                "SearchIndexResponse": {
                    "type": "object",
                    "properties": {
                        "metadata": {"$ref": "#/components/schemas/Metadata"},
                        "index": {"type": "string"},
                        "field": {"type": "string"},
                        "key_count": {"type": "integer"},
                        "entry_count": {"type": "integer"},
                        "keys": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/SearchIndexReference"},
                            },
                        },
                    },
                },
                "AlgorithmsResponse": {
                    "type": "object",
                    "properties": {
                        "total_unique_algorithms": {"type": "integer"},
                        "total_certificate_algorithm_pairs": {"type": "integer"},
                        "algorithms": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "object",
                                "properties": {
                                    "count": {"type": "integer"},
                                    "certificates": {
                                        "type": "array",
                                        "items": {"type": "integer"}
                                    }
                                }
                            }
                        },
                        "metadata": {"type": "object", "additionalProperties": True}
                    }
                },
                "CertificateIndexEntry": {
                    "type": "object",
                    "description": "Compact discovery row for a per-certificate detail JSON file",
                    "properties": {
                        "certificate_number": {"type": "string"},
                        "dataset": {"type": "string", "enum": ["active", "historical"]},
                        "path": {"type": "string", "example": "/api/certificates/5238.json"},
                        "nist_page_url": {"type": "string"},
                        "certificate_detail_url": {"type": "string"},
                        "security_policy_url": {"type": "string", "nullable": True},
                        "vendor_name": {"type": "string", "nullable": True},
                        "module_name": {"type": "string", "nullable": True},
                        "standard": {"type": "string", "nullable": True},
                        "status": {"type": "string", "nullable": True},
                        "module_type": {"type": "string", "nullable": True},
                        "overall_level": {
                            "oneOf": [{"type": "integer"}, {"type": "string"}],
                            "nullable": True,
                        },
                        "validation_date": {"type": "string", "nullable": True},
                        "validation_dates": {"type": "array", "items": {"type": "string"}},
                        "sunset_date": {"type": "string", "nullable": True},
                        "algorithms": {"type": "array", "items": {"type": "string"}},
                        "algorithm_count": {"type": "integer"},
                        "algorithm_extraction_status": {"type": "string", "nullable": True},
                        "algorithm_source": {"type": "string", "nullable": True},
                        "detail_available": {"type": "boolean"},
                    },
                },
                "CertificateIndexResponse": {
                    "type": "object",
                    "properties": {
                        "metadata": {"$ref": "#/components/schemas/Metadata"},
                        "total_certificates": {"type": "integer"},
                        "certificate_paths": {
                            "type": "object",
                            "additionalProperties": {"type": "string"},
                        },
                        "certificates": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/CertificateIndexEntry"},
                        },
                    },
                },
                "CertificateDetail": {
                    "type": "object",
                    "description": "Structured certificate detail record derived from the NIST certificate page",
                    "properties": detail_properties,
                },
                "CertificateDetailResponse": {
                    "type": "object",
                    "properties": {
                        "metadata": {
                            "type": "object",
                            "properties": {
                                "generated_at": {"type": "string", "format": "date-time"},
                                "dataset": {"type": "string"},
                                "source": {"type": "string"},
                            }
                        },
                        "certificate": {"$ref": "#/components/schemas/CertificateDetail"}
                    }
                },
                "Index": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "example": index_payload["name"]},
                        "description": {"type": "string", "example": index_payload["description"]},
                        "base_url": {"type": "string", "example": index_payload["base_url"]},
                        "endpoints": {"type": "object"},
                        "documentation": {"type": "object"},
                        "last_updated": {"type": "string", "format": "date-time"},
                        "total_modules": {"type": "integer"},
                        "total_historical_modules": {"type": "integer"},
                        "total_modules_in_process": {"type": "integer"},
                        "total_certificates_with_algorithms": {"type": "integer"},
                        "total_certificate_details": {"type": "integer"},
                        "features": {"type": "object"}
                    }
                }
            }
        }
    }

    return spec


def select_algorithm_source(
    requested_source: str = "",
    skip_algorithms: bool = False,
    cmvp_db_path: str = "",
    crawl4ai_available: bool = CRAWL4AI_AVAILABLE,
) -> str:
    """Choose the algorithm extraction source from environment-style inputs."""
    normalized = (requested_source or "").strip().lower().replace("-", "_")

    if cmvp_db_path:
        return "database"
    if skip_algorithms or normalized == "none":
        return "none"
    if normalized == "database":
        raise ValueError("ALGORITHM_SOURCE=database requires CMVP_DB_PATH.")
    if normalized in {"security_policy_pdf", "local_pdf", "pdf"}:
        return SECURITY_POLICY_ALGORITHM_SOURCE
    if normalized in {CRAWL4AI_ALGORITHM_SOURCE, "firecrawl"}:
        return CRAWL4AI_ALGORITHM_SOURCE if crawl4ai_available else SECURITY_POLICY_ALGORITHM_SOURCE
    if normalized:
        raise ValueError(
            "Unsupported ALGORITHM_SOURCE. Use crawl4ai, security_policy_pdf, database, or none."
        )
    return CRAWL4AI_ALGORITHM_SOURCE if crawl4ai_available else SECURITY_POLICY_ALGORITHM_SOURCE


def main():
    """Main entry point for the scraper."""
    print("=" * 60)
    print("NIST CMVP Data Scraper")
    print("=" * 60)
    print()

    # Check algorithm extraction options
    if FULL_REFRESH:
        print("Note: FULL_REFRESH=1 set. Cached certificate outputs will be ignored.")
    try:
        algorithm_source = select_algorithm_source(
            ALGORITHM_SOURCE_OVERRIDE,
            SKIP_ALGORITHMS,
            CMVP_DB_PATH,
            CRAWL4AI_AVAILABLE,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if CMVP_DB_PATH:
        print(f"Note: Will import algorithms from database: {CMVP_DB_PATH}")
    elif algorithm_source == CRAWL4AI_ALGORITHM_SOURCE:
        if ALGORITHM_SOURCE_OVERRIDE == "firecrawl":
            print("Note: ALGORITHM_SOURCE=firecrawl is no longer supported; using Crawl4AI instead.")
        print("Note: Will extract algorithms with Crawl4AI (local PDF parsing remains a fallback)")
    elif algorithm_source == SECURITY_POLICY_ALGORITHM_SOURCE:
        if ALGORITHM_SOURCE_OVERRIDE in {CRAWL4AI_ALGORITHM_SOURCE, "firecrawl"} and not CRAWL4AI_AVAILABLE:
            print("Note: Crawl4AI is not installed. Will extract algorithms from Security Policy PDFs locally.")
        else:
            print("Note: Will extract algorithms from Security Policy PDFs locally")
    elif algorithm_source == "none":
        print("Note: SKIP_ALGORITHMS=1 set. Algorithm extraction will be skipped.")
    print()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # Scrape all validated modules
    print("Scraping validated modules...")
    modules = scrape_all_modules()

    if not modules:
        print("No validated modules found!", file=sys.stderr)
        sys.exit(1)

    # Validate module counts to prevent silent data loss
    validate_module_count(modules, "validated modules", min_expected=100)
    print(f"\nTotal validated modules scraped: {len(modules)}")

    # Scrape historical modules
    print("\nScraping historical modules...")
    historical_modules = scrape_historical_modules()

    validate_module_count(historical_modules, "historical modules", min_expected=500)
    print(f"Total historical modules scraped: {len(historical_modules)}")

    # Scrape modules in process
    print("\nScraping modules in process...")
    modules_in_process = scrape_modules_in_process()

    # Lower threshold for in-process — this list is naturally smaller and more variable
    validate_module_count(modules_in_process, "modules in process", min_expected=20)
    print(f"Total modules in process scraped: {len(modules_in_process)}")

    # Add security policy and detail URLs to all modules
    print("\nEnriching modules with URLs...")
    modules = enrich_modules_with_urls(modules)
    historical_modules = enrich_modules_with_urls(historical_modules)

    previous_outputs = load_previous_outputs() if not FULL_REFRESH else {
        "metadata": {},
        "modules": {"active": {}, "historical": {}},
        "details": {},
    }
    if not FULL_REFRESH:
        cached_detail_count = len(previous_outputs.get("details", {}))
        print(f"Loaded {cached_detail_count} cached certificate detail records for reuse checks")

    database_algorithms_map: Dict[int, List[str]] = {}
    if algorithm_source == "database":
        print("\nImporting algorithms from database...")
        database_algorithms_map = import_algorithms_from_database(CMVP_DB_PATH)

    certificate_detail_payloads: Dict[int, Dict] = {}
    algorithms_map: Dict[int, List[str]] = {}

    print("\nBuilding active certificate records...")
    modules, active_payloads, active_algorithms, active_stats = asyncio.run(
        build_certificate_artifacts(
            modules,
            "active",
            generated_at,
            algorithm_source,
            previous_outputs,
            database_algorithms_map,
        )
    )
    certificate_detail_payloads.update(active_payloads)
    algorithms_map.update(active_algorithms)

    print("\nBuilding historical certificate records...")
    historical_modules, historical_payloads, historical_algorithms, historical_stats = asyncio.run(
        build_certificate_artifacts(
            historical_modules,
            "historical",
            generated_at,
            algorithm_source,
            previous_outputs,
            database_algorithms_map,
        )
    )
    certificate_detail_payloads.update(historical_payloads)
    algorithms_map.update(historical_algorithms)

    extraction_metrics = build_extraction_metrics(active_stats, historical_stats)

    # Prepare output directory
    output_dir = "api"

    # Create metadata
    metadata = {
        "generated_at": generated_at,
        "total_modules": len(modules),
        "total_historical_modules": len(historical_modules),
        "total_modules_in_process": len(modules_in_process),
        "total_certificates_with_algorithms": len(algorithms_map),
        "total_certificate_details": len(certificate_detail_payloads),
        "source": BASE_URL,
        "modules_in_process_source": MODULES_IN_PROCESS_URL,
        "algorithm_source": algorithm_source,
        "algorithm_cache_version": ALGORITHM_CACHE_VERSION,
        "algorithm_extraction_schema_version": ALGORITHM_EXTRACTION_SCHEMA_VERSION,
        "extraction_metrics": extraction_metrics,
        "version": "3.0"
    }

    # Save main modules data (validated)
    main_data = {
        "metadata": metadata,
        "modules": modules
    }
    save_json(main_data, f"{output_dir}/modules.json")

    # Save historical modules data
    historical_data = {
        "metadata": metadata,
        "modules": historical_modules
    }
    save_json(historical_data, f"{output_dir}/historical-modules.json")

    # Save modules in process data
    modules_in_process_data = {
        "metadata": metadata,
        "modules_in_process": modules_in_process
    }
    save_json(modules_in_process_data, f"{output_dir}/modules-in-process.json")

    for cert_number, certificate_payload in certificate_detail_payloads.items():
        detail_response = {
            "metadata": {
                "generated_at": generated_at,
                "dataset": certificate_payload.get("dataset", "active"),
                "source": certificate_payload.get("nist_page_url", get_certificate_detail_url(cert_number)),
            },
            "certificate": certificate_payload,
        }
        save_json(detail_response, f"{output_dir}/certificates/{cert_number}.json")

    current_cert_numbers = {
        cert_number
        for cert_number in (
            parse_certificate_number(module) for module in modules + historical_modules
        )
        if cert_number is not None
    }
    removed_orphans = prune_orphan_certificate_details(current_cert_numbers)

    certificate_index_data = build_certificate_index_payload(
        metadata,
        modules,
        historical_modules,
        certificate_detail_payloads,
    )
    save_json(certificate_index_data, f"{output_dir}/certificates/index.json")

    for path, search_index_payload in build_search_index_payloads(metadata, certificate_index_data).items():
        save_json(search_index_payload, path)

    data_quality_report = build_data_quality_report(
        metadata,
        modules,
        historical_modules,
        certificate_detail_payloads,
        previous_outputs,
        active_stats,
        historical_stats,
    )
    save_json(data_quality_report, f"{output_dir}/data-quality.json")
    save_json(build_examples_payload(metadata), f"{output_dir}/examples.json")

    algorithms_summary = None

    # Save algorithms summary (if available)
    if algorithms_map:
        algorithms_summary = create_algorithms_summary(algorithms_map)
        algorithms_summary["metadata"] = {
            "generated_at": metadata["generated_at"],
            "total_certificates_processed": len(algorithms_map),
            "source": algorithm_source,
            "algorithm_source": algorithm_source,
            "algorithm_cache_version": ALGORITHM_CACHE_VERSION,
            "algorithm_extraction_schema_version": ALGORITHM_EXTRACTION_SCHEMA_VERSION,
            "extraction_metrics": extraction_metrics["combined"],
        }
        save_json(algorithms_summary, f"{output_dir}/algorithms.json")
    else:
        algorithms_path = Path(output_dir) / "algorithms.json"
        if algorithms_path.exists():
            algorithms_path.unlink()
            print(f"Removed stale: {algorithms_path}")

    # Save metadata separately for quick access
    save_json(metadata, f"{output_dir}/metadata.json")

    index_data = build_index_payload(metadata, algorithms_summary)
    save_json(index_data, f"{output_dir}/index.json")

    # Generate OpenAPI spec from actual data schema
    print("\nGenerating OpenAPI spec...")
    sample_certificate_detail = next(iter(certificate_detail_payloads.values()), None)
    openapi_spec = generate_openapi_spec(
        modules,
        metadata,
        sample_certificate_detail,
        algorithms_summary,
    )
    # Save as YAML-formatted JSON (valid YAML is a superset of JSON)
    # Using JSON since we already have the json module and it's valid YAML
    save_json(openapi_spec, "openapi.json")

    print("Generating agent-friendly docs...")
    for path, content in generate_text_artifacts(
        metadata,
        modules[0] if modules else None,
        sample_certificate_detail,
        algorithms_summary,
    ).items():
        save_text(content, path)

    print("Generating JSON Schema artifacts...")
    schema_artifacts = generate_json_schema_artifacts(algorithms_summary)
    for path, schema in schema_artifacts.items():
        save_json(schema, path)
    schema_dir = Path(output_dir) / "schemas"
    if schema_dir.exists():
        expected_schema_paths = {Path(path) for path in schema_artifacts}
        for stale_schema in schema_dir.glob("*.schema.json"):
            if stale_schema not in expected_schema_paths:
                stale_schema.unlink()
                print(f"Removed stale: {stale_schema}")

    print("\n" + "=" * 60)
    print("Scraping completed successfully!")
    print("=" * 60)
    print(f"\nSummary:")
    print(f"  - Validated modules: {len(modules)}")
    print(f"  - Historical modules: {len(historical_modules)}")
    print(f"  - Modules in process: {len(modules_in_process)}")
    if algorithms_map:
        print(f"  - Certificates with algorithms: {len(algorithms_map)}")
    print(f"  - Certificate detail records: {len(certificate_detail_payloads)}")
    if removed_orphans:
        print(f"  - Removed stale certificate detail files: {removed_orphans}")
    print(f"  - Algorithm source: {algorithm_source}")
    print(
        "  - Active detail reuse: "
        f"{active_stats['html_reused']} reused, {active_stats['html_refreshed']} refreshed, {active_stats['html_failed']} failed"
    )
    print(
        "  - Historical detail reuse: "
        f"{historical_stats['html_reused']} reused, {historical_stats['html_refreshed']} refreshed, {historical_stats['html_failed']} failed"
    )
    if algorithm_source in CACHEABLE_ALGORITHM_SOURCES:
        print(
            "  - Active algorithm reuse: "
            f"{active_stats['pdf_reused']} reused, {active_stats['pdf_refreshed']} refreshed, "
            f"{active_stats['pdf_failed']} failed, {active_stats['pdf_cache_hits']} PDF cache hits, "
            f"{active_stats['algorithm_misses']} misses"
        )
        print(
            "  - Historical algorithm reuse: "
            f"{historical_stats['pdf_reused']} reused, {historical_stats['pdf_refreshed']} refreshed, "
            f"{historical_stats['pdf_failed']} failed, {historical_stats['pdf_cache_hits']} PDF cache hits, "
            f"{historical_stats['algorithm_misses']} misses"
        )
    print(f"  - OpenAPI spec: openapi.json")
    print(f"\nOutput files saved to: {output_dir}/")


if __name__ == "__main__":
    main()
