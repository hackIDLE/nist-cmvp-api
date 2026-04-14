#!/usr/bin/env python3
"""
NIST CMVP Data Scraper

This script scrapes the NIST Cryptographic Module Validation Program (CMVP)
validated modules database and saves the data as JSON files for a static API.

Features:
- Scrapes validated, historical, and in-process modules
- Extracts algorithm information from certificate detail pages using crawl4ai
- Can import algorithm data from existing NIST-CMVP-ReportGen database
- Generates security policy PDF URLs

Environment Variables:
    NIST_SEARCH_PATH: Override the search path (default: /all)
                      Example: export NIST_SEARCH_PATH="/all"
    SKIP_ALGORITHMS: Set to "1" to skip algorithm extraction (faster scraping)
    CMVP_DB_PATH: Path to existing cmvp.db from NIST-CMVP-ReportGen project
                  If set, algorithm data will be imported from this database
"""

import asyncio
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# Crawl4AI imports (for algorithm extraction)
try:
    from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, CacheMode
    CRAWL4AI_AVAILABLE = True
except ImportError:
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

# Path to NIST-CMVP-ReportGen database (if available for importing algorithms)
CMVP_DB_PATH = os.getenv("CMVP_DB_PATH", "")

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

    security_policy_url = summary_module.get("security_policy_url")
    if not security_policy_url:
        security_policy = next(
            (item["url"] for item in related_files if item["label"].lower() == "security policy"),
            None,
        )
        security_policy_url = security_policy

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
        "security_level_exceptions": detail_fields.get("security_level_exceptions", []),
        "related_files": related_files,
        "validation_history": validation_history,
        "vendor": vendor,
        "algorithms": algorithms,
    }


def build_certificate_detail_payloads(
    modules: List[Dict],
    dataset: str,
    generated_at: str,
) -> Dict[int, Dict]:
    """
    Fetch and parse NIST detail pages into static per-certificate JSON payloads.

    Args:
        modules: Summary module rows for a dataset
        dataset: Dataset label (active or historical)
        generated_at: Shared generation timestamp for this scraper run

    Returns:
        Dictionary keyed by certificate number
    """
    payloads: Dict[int, Dict] = {}
    total = len(modules)
    success = 0
    failed = 0

    print(f"\nGenerating {dataset} certificate detail records ({total} certificates)...")

    for index, module in enumerate(modules, 1):
        cert_num_str = str(module.get("Certificate Number", "")).strip()
        if not cert_num_str:
            continue

        try:
            cert_num = int(cert_num_str)
        except ValueError:
            failed += 1
            continue

        html = fetch_page(get_certificate_detail_url(cert_num), timeout=30, retries=3)
        if not html:
            failed += 1
            continue

        try:
            payloads[cert_num] = parse_certificate_detail_page(
                html,
                cert_num,
                summary_module=module,
                dataset=dataset,
                generated_at=generated_at,
            )
            success += 1
        except Exception as exc:
            failed += 1
            print(f"Warning: Failed to parse certificate {cert_num}: {exc}", file=sys.stderr)

        if index % 100 == 0 or index == total:
            print(f"  Progress: {index}/{total} ({success} success, {failed} failed)")

        time.sleep(0.1)

    return payloads


def parse_algorithms_from_markdown(markdown: str) -> Tuple[List[str], List[str]]:
    """
    Extract algorithm information from markdown text.

    Returns both detailed algorithm entries (full names with parameters)
    and simplified categories for display.

    Args:
        markdown: Markdown text from certificate detail page

    Returns:
        Tuple of (detailed_algorithms, categories)
        - detailed_algorithms: Full algorithm names like "HMAC-SHA2-256", "ECDSA SigGen (FIPS186-4)"
        - categories: Simplified names like "HMAC", "ECDSA", "AES"
    """
    detailed: List[str] = []
    categories: Set[str] = set()

    # Find lines that look like algorithm entries
    # On NIST pages, algorithms appear as plain text lines before [Axxxx] validation links
    for line in markdown.split('\n'):
        line = line.strip()

        # Skip empty lines, markdown links, headers, tables, and bullets
        if not line or len(line) < 3:
            continue
        if line.startswith(('[', '#', '|', '---', '*')):
            continue

        # Skip lines with UI/junk patterns (page chrome, not algorithms)
        line_lower = line.lower()
        if any(pattern in line_lower for pattern in SKIP_PATTERNS):
            continue

        # Skip overly long lines (likely sentences, not algorithm names)
        if len(line) > 80:
            continue

        # Check if this line contains an algorithm keyword
        line_upper = line.upper()
        for kw in ALGORITHM_KEYWORDS:
            if kw in line_upper:
                # This looks like an algorithm entry - add the full line as detailed
                if line not in detailed:
                    detailed.append(line)
                # Add the category
                categories.add(kw)
                break

    return detailed, sorted(categories)


def parse_certificate_details_from_markdown(markdown: str) -> Dict:
    """
    Extract certificate details from markdown text.

    Args:
        markdown: Markdown text from certificate detail page

    Returns:
        Dictionary with certificate details
    """
    details = {}
    lines = markdown.split('\n')

    # Field patterns to look for (label: field_name)
    field_patterns = {
        'module name': 'module_name',
        'standard': 'standard',
        'status': 'status',
        'sunset date': 'sunset_date',
        'overall level': 'overall_level',
        'caveat': 'caveat',
        'module type': 'module_type',
        'embodiment': 'embodiment',
        'description': 'description',
        'validation date': 'validation_date',
        'laboratory': 'lab',
        'vendor': 'vendor_name',
    }

    for i, line in enumerate(lines):
        line_lower = line.lower().strip()

        for pattern, field in field_patterns.items():
            # Match pattern at start of line or as table cell (not just anywhere in line)
            # This prevents matching "nist-information-quality-standards" when looking for "standard"
            is_field_label = (
                line_lower.startswith(pattern) or
                line_lower.startswith(f'| {pattern}')
            )

            if is_field_label:
                # Try to extract value from same line (after colon or pipe)
                if '|' in line:
                    parts = [p.strip() for p in line.split('|') if p.strip()]
                    # In table format "| Field | Value |", parts would be ['Field', 'Value']
                    if len(parts) >= 2:
                        value = parts[1]  # Second non-empty part is the value
                        if value and value != '---':
                            details[field] = value
                elif ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        value = parts[1].strip()
                        if value:
                            details[field] = value
                # Also check next line for value
                elif i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    if next_line and not any(p in next_line.lower() for p in field_patterns.keys()):
                        details[field] = next_line

    # Extract overall level as integer
    if 'overall_level' in details:
        match = re.search(r'\d+', str(details['overall_level']))
        if match:
            details['overall_level'] = int(match.group())

    # Extract algorithms (both detailed and categories)
    detailed_algorithms, categories = parse_algorithms_from_markdown(markdown)
    details['algorithms'] = categories  # Simplified categories for display
    details['algorithms_detailed'] = detailed_algorithms  # Full algorithm entries

    return details


async def crawl_certificate_page(crawler, cert_number: int) -> str:
    """
    Crawl a certificate page and return markdown.

    Args:
        crawler: AsyncWebCrawler instance
        cert_number: Certificate number to crawl

    Returns:
        Markdown content of the page, or empty string on failure
    """
    url = get_certificate_detail_url(cert_number)
    try:
        result = await crawler.arun(
            url=url,
            config=CrawlerRunConfig(
                cache_mode=CacheMode.BYPASS,
                delay_before_return_html=2.0  # Wait for JS to load dynamic content
            )
        )
        return result.markdown if result.success else ""
    except Exception:
        return ""


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


async def extract_certificate_details(cert_numbers: List[int]) -> Dict[int, Dict]:
    """
    Extract full details for a list of certificates using crawl4ai.

    Args:
        cert_numbers: List of certificate numbers to process

    Returns:
        Dictionary mapping certificate numbers to detail dictionaries
    """
    if not CRAWL4AI_AVAILABLE:
        print("Warning: crawl4ai not available. Skipping detail extraction.", file=sys.stderr)
        print("Install with: pip install crawl4ai && crawl4ai-setup", file=sys.stderr)
        return {}

    details_map = {}
    total = len(cert_numbers)
    success = 0
    failed = 0

    print(f"\nExtracting details from {total} certificate pages...")

    async with AsyncWebCrawler() as crawler:
        for i, cert_num in enumerate(cert_numbers, 1):
            try:
                markdown = await crawl_certificate_page(crawler, cert_num)
                if markdown:
                    details = parse_certificate_details_from_markdown(markdown)
                    if details:
                        details_map[cert_num] = details
                    success += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

            if i % 50 == 0 or i == total:
                print(f"  Progress: {i}/{total} ({success} success, {failed} failed)")

            # Small delay to avoid rate limiting
            await asyncio.sleep(0.3)

    print(f"Detail extraction complete: {len(details_map)} certificates processed")
    return details_map


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
    Add full certificate details to modules from the details map.

    Args:
        modules: List of module dictionaries
        details_map: Dictionary mapping certificate numbers to detail dictionaries

    Returns:
        List of modules with added detail fields
    """
    for module in modules:
        cert_num_str = module.get("Certificate Number", "")
        if cert_num_str:
            try:
                cert_num = int(cert_num_str)
                if cert_num in details_map:
                    details = details_map[cert_num]
                    # Add all detail fields to module
                    for key, value in details.items():
                        if value:  # Only add non-empty values
                            module[key] = value
            except ValueError:
                pass
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


def generate_openapi_spec(modules: List[Dict], metadata: Dict, sample_certificate_detail: Optional[Dict] = None) -> Dict:
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
    # Build module schema properties from actual field names
    sample = modules[0] if modules else {}
    module_properties = {}
    for key, value in sample.items():
        if isinstance(value, list):
            module_properties[key] = {
                "type": "array",
                "items": {"type": "string"},
                "example": value[:3] if value else []
            }
        elif isinstance(value, int):
            module_properties[key] = {
                "type": "integer",
                "example": value
            }
        else:
            module_properties[key] = {
                "type": "string",
                "example": str(value)
            }

    detail_properties = {}
    for key, value in (sample_certificate_detail or {}).items():
        if isinstance(value, list):
            item_example = value[0] if value else {}
            if isinstance(item_example, dict):
                detail_properties[key] = {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": True
                    }
                }
            else:
                detail_properties[key] = {
                    "type": "array",
                    "items": {"type": "string"},
                    "example": value[:3] if value else []
                }
        elif isinstance(value, dict):
            detail_properties[key] = {
                "type": "object",
                "additionalProperties": True
            }
        elif isinstance(value, int):
            detail_properties[key] = {
                "type": "integer",
                "example": value
            }
        else:
            detail_properties[key] = {
                "type": "string",
                "nullable": value is None,
                "example": str(value) if value is not None else ""
            }

    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "NIST CMVP Data API",
            "description": (
                "Static JSON API for NIST Cryptographic Module Validation Program data. "
                "Auto-updated weekly via GitHub Actions. "
                "Unofficial project - see https://csrc.nist.gov/projects/cryptographic-module-validation-program for authoritative data."
            ),
            "version": metadata.get("version", "2.0"),
            "contact": {
                "url": "https://github.com/hackIDLE/NIST-CMVP-API"
            }
        },
        "servers": [
            {
                "url": "https://hackidle.github.io/NIST-CMVP-API",
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
                        "algorithm_source": {"type": "string", "example": metadata.get("algorithm_source", "")},
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
                        }
                    }
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
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "endpoints": {"type": "object"},
                        "last_updated": {"type": "string", "format": "date-time"},
                        "total_modules": {"type": "integer"},
                        "total_historical_modules": {"type": "integer"},
                        "total_modules_in_process": {"type": "integer"},
                        "features": {"type": "object"}
                    }
                }
            }
        }
    }

    return spec


def main():
    """Main entry point for the scraper."""
    print("=" * 60)
    print("NIST CMVP Data Scraper")
    print("=" * 60)
    print()

    # Check algorithm extraction options
    algorithm_source = "none"
    if CMVP_DB_PATH:
        print(f"Note: Will import algorithms from database: {CMVP_DB_PATH}")
        algorithm_source = "database"
    elif not SKIP_ALGORITHMS:
        if CRAWL4AI_AVAILABLE:
            print("Note: Will extract algorithms using crawl4ai (this may take a while)")
            algorithm_source = "crawl4ai"
        else:
            print("Note: crawl4ai not installed. Algorithm extraction will be skipped.")
            print("Install with: pip install crawl4ai && crawl4ai-setup")
    else:
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

    # Get algorithms (from database or by crawling)
    algorithms_map = {}

    if algorithm_source == "database":
        # Import from existing database (fast)
        print("\nImporting algorithms from database...")
        algorithms_map = import_algorithms_from_database(CMVP_DB_PATH)
        modules = enrich_modules_with_algorithms(modules, algorithms_map)
        # Also enrich historical modules with algorithms
        historical_modules = enrich_modules_with_algorithms(historical_modules, algorithms_map)

    elif algorithm_source == "crawl4ai":
        # Extract full certificate details via crawl4ai (slow but comprehensive)
        cert_numbers = []
        for module in modules:
            cert_num_str = module.get("Certificate Number", "")
            if cert_num_str:
                try:
                    cert_numbers.append(int(cert_num_str))
                except ValueError:
                    pass

        if cert_numbers:
            # Extract full details including algorithms, caveats, etc.
            details_map = asyncio.run(extract_certificate_details(cert_numbers))
            modules = enrich_modules_with_details(modules, details_map)

            # Build algorithms_map from details for the summary
            for cert_num, details in details_map.items():
                if 'algorithms' in details and details['algorithms']:
                    algorithms_map[cert_num] = details['algorithms']

    certificate_detail_payloads = {}
    if modules:
        certificate_detail_payloads.update(
            build_certificate_detail_payloads(modules, "active", generated_at)
        )
    if historical_modules:
        certificate_detail_payloads.update(
            build_certificate_detail_payloads(historical_modules, "historical", generated_at)
        )

    for module in modules:
        cert = str(module.get("Certificate Number", "")).strip()
        module["detail_available"] = cert.isdigit() and int(cert) in certificate_detail_payloads
    for module in historical_modules:
        cert = str(module.get("Certificate Number", "")).strip()
        module["detail_available"] = cert.isdigit() and int(cert) in certificate_detail_payloads

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
        "version": "2.0"
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

    # Save algorithms summary (if available)
    if algorithms_map:
        algorithms_summary = create_algorithms_summary(algorithms_map)
        algorithms_summary["metadata"] = {
            "generated_at": metadata["generated_at"],
            "total_certificates_processed": len(algorithms_map),
            "source": algorithm_source
        }
        save_json(algorithms_summary, f"{output_dir}/algorithms.json")

    # Save metadata separately for quick access
    save_json(metadata, f"{output_dir}/metadata.json")

    # Create index page
    endpoints = {
        "modules": "/api/modules.json",
        "historical_modules": "/api/historical-modules.json",
        "modules_in_process": "/api/modules-in-process.json",
        "metadata": "/api/metadata.json",
        "certificate_detail_template": "/api/certificates/{certificate}.json",
    }
    if algorithms_map:
        endpoints["algorithms"] = "/api/algorithms.json"

    index_data = {
        "name": "NIST CMVP Data API",
        "description": "Static API for NIST Cryptographic Module Validation Program validated modules with algorithm information and security policy links",
        "endpoints": endpoints,
        "last_updated": metadata["generated_at"],
        "total_modules": len(modules),
        "total_historical_modules": len(historical_modules),
        "total_modules_in_process": len(modules_in_process),
        "total_certificates_with_algorithms": len(algorithms_map),
        "total_certificate_details": len(certificate_detail_payloads),
        "features": {
            "security_policy_urls": True,
            "certificate_detail_urls": True,
            "algorithm_extraction": algorithm_source != "none",
            "certificate_detail_records": True,
        }
    }
    save_json(index_data, f"{output_dir}/index.json")

    # Generate OpenAPI spec from actual data schema
    print("\nGenerating OpenAPI spec...")
    sample_certificate_detail = next(iter(certificate_detail_payloads.values()), None)
    openapi_spec = generate_openapi_spec(modules, metadata, sample_certificate_detail)
    # Save as YAML-formatted JSON (valid YAML is a superset of JSON)
    # Using JSON since we already have the json module and it's valid YAML
    save_json(openapi_spec, "openapi.json")

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
    print(f"  - Algorithm source: {algorithm_source}")
    print(f"  - OpenAPI spec: openapi.json")
    print(f"\nOutput files saved to: {output_dir}/")


if __name__ == "__main__":
    main()
