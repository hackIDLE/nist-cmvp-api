#!/usr/bin/env python3
"""
Test script for the NIST CMVP scraper.
Tests the parsing logic with sample HTML.
"""

import json
import sys
import tempfile
from pathlib import Path
from scraper import (
    build_certificate_fingerprint,
    build_index_payload,
    extract_legacy_algorithm_section,
    generate_openapi_spec,
    generate_text_artifacts,
    parse_algorithms_from_firecrawl_markdown,
    parse_algorithms_from_policy_text,
    parse_certificate_detail_page,
    parse_modules_table,
    prune_orphan_certificate_details,
)


def test_parse_simple_table():
    """Test parsing a simple HTML table."""
    html = """
    <html>
        <body>
            <table>
                <thead>
                    <tr>
                        <th>Certificate Number</th>
                        <th>Vendor</th>
                        <th>Module Name</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>1234</td>
                        <td>Test Vendor</td>
                        <td><a href="/test">Test Module</a></td>
                    </tr>
                    <tr>
                        <td>5678</td>
                        <td>Another Vendor</td>
                        <td>Another Module</td>
                    </tr>
                </tbody>
            </table>
        </body>
    </html>
    """
    
    modules = parse_modules_table(html)
    
    assert len(modules) == 2, f"Expected 2 modules, got {len(modules)}"
    assert modules[0]["Certificate Number"] == "1234", "First module certificate mismatch"
    assert modules[0]["Vendor"] == "Test Vendor", "First module vendor mismatch"
    assert modules[0]["Module Name"] == "Test Module", "First module name mismatch"
    assert "Module Name_url" in modules[0], "Expected URL field for module name"
    assert modules[0]["Module Name_url"] == "https://csrc.nist.gov/test", "URL should be absolute"
    
    assert modules[1]["Certificate Number"] == "5678", "Second module certificate mismatch"
    
    print("✓ Simple table test passed")


def test_parse_table_without_thead():
    """Test parsing a table without explicit thead."""
    html = """
    <html>
        <body>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                </tr>
                <tr>
                    <td>100</td>
                    <td>Module A</td>
                </tr>
            </table>
        </body>
    </html>
    """
    
    modules = parse_modules_table(html)
    
    assert len(modules) == 1, f"Expected 1 module, got {len(modules)}"
    assert modules[0]["ID"] == "100", "Module ID mismatch"
    assert modules[0]["Name"] == "Module A", "Module name mismatch"
    
    print("✓ Table without thead test passed")


def test_parse_empty_table():
    """Test parsing an empty table."""
    html = """
    <html>
        <body>
            <table>
                <thead>
                    <tr>
                        <th>Column 1</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </body>
    </html>
    """
    
    modules = parse_modules_table(html)
    
    assert len(modules) == 0, f"Expected 0 modules, got {len(modules)}"
    
    print("✓ Empty table test passed")


def test_parse_historical_modules_table():
    """Test parsing a table with historical modules format."""
    html = """
    <html>
        <body>
            <table>
                <thead>
                    <tr>
                        <th>Certificate Number</th>
                        <th>Vendor Name</th>
                        <th>Module Name</th>
                        <th>Module Type</th>
                        <th>Validation Date</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><a href="/cert/9999">9999</a></td>
                        <td>Historical Vendor</td>
                        <td>Historical Crypto Module</td>
                        <td>Software</td>
                        <td>01/01/2010</td>
                    </tr>
                    <tr>
                        <td><a href="/cert/8888">8888</a></td>
                        <td>Old Corp</td>
                        <td>Legacy Module</td>
                        <td>Hardware</td>
                        <td>12/31/2009</td>
                    </tr>
                </tbody>
            </table>
        </body>
    </html>
    """
    
    modules = parse_modules_table(html)
    
    assert len(modules) == 2, f"Expected 2 modules, got {len(modules)}"
    assert modules[0]["Certificate Number"] == "9999", "First historical module certificate mismatch"
    assert modules[0]["Vendor Name"] == "Historical Vendor", "First historical module vendor mismatch"
    assert modules[0]["Module Name"] == "Historical Crypto Module", "First historical module name mismatch"
    assert "Certificate Number_url" in modules[0], "Expected URL field for certificate number"
    
    assert modules[1]["Certificate Number"] == "8888", "Second historical module certificate mismatch"
    assert modules[1]["Validation Date"] == "12/31/2009", "Second historical module date mismatch"
    
    print("✓ Historical modules table test passed")


def test_parse_modules_in_process():
    """Test parsing modules in process table structure."""
    html = """
    <html>
        <body>
            <table>
                <thead>
                    <tr>
                        <th>Lab Code</th>
                        <th>Vendor Name</th>
                        <th>Module Name</th>
                        <th>Module Type</th>
                        <th>Module Version</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>1234</td>
                        <td>Test Vendor</td>
                        <td><a href="/modules/test">Test Module In Process</a></td>
                        <td>Software</td>
                        <td>1.0</td>
                    </tr>
                </tbody>
            </table>
        </body>
    </html>
    """
    
    modules = parse_modules_table(html)
    
    assert len(modules) == 1, f"Expected 1 module, got {len(modules)}"
    assert modules[0]["Lab Code"] == "1234", "Lab Code mismatch"
    assert modules[0]["Vendor Name"] == "Test Vendor", "Vendor Name mismatch"
    assert modules[0]["Module Name"] == "Test Module In Process", "Module Name mismatch"
    assert modules[0]["Module Type"] == "Software", "Module Type mismatch"
    assert modules[0]["Module Version"] == "1.0", "Module Version mismatch"
    assert "Module Name_url" in modules[0], "Expected URL field for module name"
    
    print("✓ Modules in process table test passed")


def test_parse_certificate_detail_page():
    """Test parsing a NIST-style certificate detail page."""
    html = """
    <html>
      <body>
        <div class="panel panel-default">
          <div class="panel-heading"><h4 class="panel-title">Details</h4></div>
          <div class="panel-body">
            <div class="row padrow">
              <div class="col-md-3"><span>Module Name</span></div>
              <div class="col-md-9" id="module-name">OVHCloud OKMS Provider based on the OpenSSL FIPS Provider</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3">Standard</div>
              <div class="col-md-9" id="module-standard">FIPS 140-3</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3">Status</div>
              <div class="col-md-9">Active</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Sunset Date</span></div>
              <div class="col-md-9">3/10/2030</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Overall Level</span></div>
              <div class="col-md-9">1</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Caveat</span></div>
              <div class="col-md-9"><span class="alert-danger">When operated in approved mode.</span></div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Security Level Exceptions</span></div>
              <div class="col-md-9">
                <ul class="list-left15pxPadding">
                  <li>Physical security: N/A</li>
                  <li>Life-cycle assurance: Level 3</li>
                </ul>
              </div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Module Type</span></div>
              <div class="col-md-9">Software</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Embodiment</span></div>
              <div class="col-md-9" id="embodiment-name">MultiChipStand</div>
            </div>
            <div class="row padrow">
              <div class="col-md-3"><span>Description</span></div>
              <div class="col-md-9">A software library providing cryptographic functionality.</div>
            </div>
          </div>
        </div>

        <div class="panel panel-default">
          <div class="panel-heading"><h4 class="panel-title">Vendor</h4></div>
          <div class="panel-body">
            <a href="https://corporate.ovhcloud.com/en/">OVH SAS</a><br />
            <span class="indent">2 RUE KELLERMANN</span><br />
            <span class="indent">ROUBAIX 59100</span><br />
            <span class="indent">FRANCE</span><br /><br />
            <div style="font-size: 0.9em;">
              <span>
                Data security team<br />
                <span class="indent"><a class="__cf_email__" data-cfemail="b5daded8c6ead3dcc5c6f5dac3dd9bdbd0c1" href="/cdn-cgi/l/email-protection">[email&#160;protected]</a></span><br />
                <span class="indent">Phone: +33 3 20 82 73 32</span><br />
              </span>
            </div>
          </div>
        </div>

        <div class="panel panel-default">
          <div class="panel-heading"><h4 class="panel-title">Related Files</h4></div>
          <div class="panel-body">
            <a href="/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5203.pdf">Security Policy</a><br />
            <a href="https://example.test/other.pdf">Implementation Guidance</a>
          </div>
        </div>

        <div class="panel panel-default">
          <div class="panel-heading"><h4 class="panel-title">Validation History</h4></div>
          <div class="panel-body">
            <table class="table table-condensed table-striped nolinetable" id="validation-history-table">
              <thead>
                <tr><th>Date</th><th>Type</th><th>Lab</th></tr>
              </thead>
              <tbody>
                <tr><td class="text-nowrap">3/21/2026</td><td>Initial</td><td>Lightship Security, Inc.</td></tr>
                <tr><td class="text-nowrap">4/01/2026</td><td>Updated</td><td>Lightship Security, Inc.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </body>
    </html>
    """

    payload = parse_certificate_detail_page(
        html,
        5203,
        summary_module={
            "Vendor Name": "OVH SAS",
            "Module Name": "OVHCloud OKMS Provider based on the OpenSSL FIPS Provider",
            "algorithms": ["AES", "HMAC"],
            "security_policy_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5203.pdf",
        },
        dataset="active",
        generated_at="2026-03-26T00:00:00.000000Z",
    )

    assert payload["certificate_number"] == "5203", "Certificate number mismatch"
    assert payload["dataset"] == "active", "Dataset mismatch"
    assert payload["module_name"] == "OVHCloud OKMS Provider based on the OpenSSL FIPS Provider", "Module name mismatch"
    assert payload["standard"] == "FIPS 140-3", "Standard mismatch"
    assert payload["status"] == "Active", "Status mismatch"
    assert payload["sunset_date"] == "3/10/2030", "Sunset date mismatch"
    assert payload["overall_level"] == 1, "Overall level mismatch"
    assert payload["security_level_exceptions"] == ["Physical security: N/A", "Life-cycle assurance: Level 3"], "Security level exceptions mismatch"
    assert payload["vendor"]["name"] == "OVH SAS", "Vendor name mismatch"
    assert payload["vendor"]["contact_name"] == "Data security team", "Vendor contact mismatch"
    assert payload["vendor"]["contact_email"] == "okms_fips@ovh.net", "Vendor email mismatch"
    assert payload["vendor"]["contact_phone"] == "+33 3 20 82 73 32", "Vendor phone mismatch"
    assert payload["related_files"][0]["label"] == "Security Policy", "Related file label mismatch"
    assert payload["related_files"][0]["url"].endswith("140sp5203.pdf"), "Related file URL mismatch"
    assert len(payload["validation_history"]) == 2, "Validation history row count mismatch"
    assert payload["validation_history"][1]["type"] == "Updated", "Validation history type mismatch"
    assert payload["validation_dates"] == ["3/21/2026", "4/01/2026"], "Validation dates mismatch"
    assert payload["algorithms"] == ["AES", "HMAC"], "Algorithm list mismatch"

    print("✓ Certificate detail page test passed")


def test_parse_algorithms_from_policy_text():
    """Test extracting algorithms from Security Policy text without leaking contact data."""
    policy_text = """
    Prepared for:
    Akeyless Security ltd.
    Shai Onn
    shai@akeyless.io

    Table of Contents
    2.5 Algorithms ........................................ 8
    2.6 Security Function Implementations ............... 15

    2.5 Algorithms
    Approved Algorithms:
    Cipher
    Algorithm CAVP Cert Properties Reference
    AES-CBC A4481 Direction - Decrypt, Encrypt SP 800-38A
    Key Length - 128, 192, 256
    AES-GCM A4481 Direction - Decrypt, Encrypt SP 800-38D
    IV Generation - External, Internal
    HMAC SHA2-256 A4481 Message Authentication FIPS 198-1
    Table 6: Approved Algorithms - Cipher
    2.6 Security Function Implementations
    """

    detailed, categories = parse_algorithms_from_policy_text(policy_text)

    assert any("AES-CBC" in entry for entry in detailed), "Expected AES-CBC detailed entry"
    assert any("AES-GCM" in entry for entry in detailed), "Expected AES-GCM detailed entry"
    assert any("HMAC" in entry for entry in detailed), "Expected HMAC detailed entry"
    assert all("Shai Onn" not in entry for entry in detailed), "Contact names must not leak into algorithms"
    assert all("@" not in entry for entry in detailed), "Email addresses must not leak into algorithms"
    assert categories == ["AES", "HMAC"], "Expected normalized algorithm categories"

    print("✓ Security Policy algorithm parsing test passed")


def test_parse_algorithms_from_legacy_policy_text():
    """Test extracting coarse categories from older FIPS 140-2 approved-function sections."""
    policy_text = """
    Table of contents
    3.4 Algorithms ........................................ 11
    3.5 Allowed Algorithms ............................... 15

    3.4 Algorithms
    Table 7 lists the approved algorithms, the CAVP certificates, and other associated information.
    Algorithm
    AES
    DRBG
    SHA-256, SHA-384, SHA-512
    HMAC-SHA-256
    KAS-ECC-SSC
    KDF TLS
    TLS v1.2
    Table 7: Approved Cryptographic Algorithms

    3.5 Allowed Algorithms
    Table 8 describes the non-approved but allowed algorithms in FIPS mode:
    Algorithm
    Triple-DES
    """

    detailed, categories = parse_algorithms_from_policy_text(policy_text)

    assert detailed == [], "Legacy fallback should preserve coarse categories without fabricated detail rows"
    assert categories == ["AES", "DRBG", "HMAC", "KAS", "KDF", "SHA", "TLS"], "Expected legacy approved-section categories"
    assert "DES" not in categories, "Non-approved section content must not leak into approved categories"

    print("✓ Legacy Security Policy parsing test passed")


def test_extract_legacy_algorithm_section_prefers_body_over_toc():
    """Legacy extractor should use the real section body instead of the table of contents copy."""
    policy_text = """
    Table of contents
    4.1.1 FIPS Approved Algorithms ........ 12
    4.1.2 FIPS Non-Approved but Allowed Algorithms ........ 16

    4.1.1 FIPS Approved Algorithms
    The module supports the following FIPS-approved cryptographic algorithms.
    Table 9 : FIPS Approved Algorithms
    AES
    DRBG
    KDF TLS
    """

    section = extract_legacy_algorithm_section(policy_text)

    assert "The module supports the following FIPS-approved cryptographic algorithms." in section, "Expected body content, not just TOC content"
    assert "........ 12" not in section, "TOC dot leaders should not outrank the real section body"

    print("✓ Legacy algorithm section TOC preference test passed")


def test_parse_algorithms_from_firecrawl_markdown():
    """Test parsing algorithm tables from Firecrawl markdown output."""
    markdown = """
    2.5 Algorithms

    Approved Algorithms:

    | Algorithm | CAVP Cert | Properties | Reference |
    | --- | --- | --- | --- |
    | AES-CBC | A4481 | Direction - Decrypt, Encrypt Key Length - 128, 192, 256 | SP 800-38A |
    | HMAC SHA2-256 | A4481 | Message Authentication | FIPS 198-1 |
    | RSA SigGen | A4481 | Modulo - 2048, 3072 | FIPS 186-4 |
    |  |  | Key Transport Method - KTS-OAEP-basic |  |

    2.6 Security Function Implementations
    """

    detailed, categories = parse_algorithms_from_firecrawl_markdown(markdown)

    assert any("AES-CBC" in entry for entry in detailed), "Expected AES-CBC row from Firecrawl markdown"
    assert any("HMAC SHA2-256" in entry for entry in detailed), "Expected HMAC row from Firecrawl markdown"
    assert any("RSA SigGen" in entry for entry in detailed), "Expected RSA row from Firecrawl markdown"
    assert all("Key Transport Method" not in entry for entry in detailed), "Blank algorithm-name rows must be ignored"
    assert categories == ["AES", "HMAC", "RSA"], "Expected normalized categories from Firecrawl markdown"

    print("✓ Firecrawl markdown algorithm parsing test passed")


def test_build_certificate_fingerprint():
    """Test that certificate fingerprints are stable and change when summary fields change."""
    base_row = {
        "Certificate Number": "5238",
        "Vendor Name": "SUSE LLC",
        "Module Name": "SUSE Linux Enterprise OpenSSL 1 Cryptographic Module",
        "Module Type": "Software",
        "Validation Date": "04/10/2026",
        "security_policy_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5238.pdf",
        "certificate_detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5238",
    }

    same_row = dict(base_row)
    changed_row = dict(base_row)
    changed_row["Validation Date"] = "04/11/2026"

    fingerprint = build_certificate_fingerprint(base_row, "active")
    assert fingerprint == build_certificate_fingerprint(same_row, "active"), "Fingerprint should be stable for unchanged rows"
    assert fingerprint != build_certificate_fingerprint(changed_row, "active"), "Fingerprint should change when summary fields change"
    assert fingerprint != build_certificate_fingerprint(base_row, "historical"), "Fingerprint should change when dataset changes"

    print("✓ Certificate fingerprint test passed")


def test_prune_orphan_certificate_details():
    """Test that stale certificate detail files are removed only for missing certs."""
    with tempfile.TemporaryDirectory() as temp_dir:
        detail_dir = Path(temp_dir)
        (detail_dir / "100.json").write_text("{}", encoding="utf-8")
        (detail_dir / "200.json").write_text("{}", encoding="utf-8")
        (detail_dir / "notes.json").write_text("{}", encoding="utf-8")

        removed = prune_orphan_certificate_details({100}, detail_dir)

        assert removed == 1, "Expected one orphaned certificate detail file to be removed"
        assert (detail_dir / "100.json").exists(), "Current certificate detail file should be preserved"
        assert not (detail_dir / "200.json").exists(), "Missing certificate detail file should be removed"
        assert (detail_dir / "notes.json").exists(), "Non-certificate files should be ignored"

    print("✓ Orphan certificate cleanup test passed")


def test_generate_agent_docs():
    """Test the generated agent-friendly documentation artifacts."""
    metadata = {
        "generated_at": "2026-04-12T03:10:00.961597Z",
        "total_modules": 1086,
        "total_historical_modules": 4141,
        "total_modules_in_process": 331,
        "total_certificates_with_algorithms": 374,
        "total_certificate_details": 5227,
        "source": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search",
        "modules_in_process_source": "https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/modules-in-process-list",
        "algorithm_source": "firecrawl",
        "version": "3.0",
    }
    sample_module = {
        "Certificate Number": "5238",
        "Vendor Name": "SUSE LLC",
        "Module Name": "SUSE Linux Enterprise OpenSSL 1 Cryptographic Module",
        "Module Type": "Software",
        "Validation Date": "04/10/2026",
        "standard": "FIPS 140-3",
        "status": "Active",
        "overall_level": 1,
        "sunset_date": "4/9/2031",
        "algorithms": ["AES", "HMAC", "RSA"],
        "security_policy_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5238.pdf",
        "certificate_detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5238",
        "detail_available": True,
        "description": "OpenSSL is an open-source library of various cryptographic algorithms written mainly in C.",
    }
    sample_detail = {
        "certificate_number": "5238",
        "dataset": "active",
        "generated_at": metadata["generated_at"],
        "nist_page_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5238",
        "certificate_detail_url": "https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5238",
        "security_policy_url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5238.pdf",
        "vendor_name": "SUSE LLC",
        "module_name": "SUSE Linux Enterprise OpenSSL 1 Cryptographic Module",
        "standard": "FIPS 140-3",
        "status": "Active",
        "module_type": "Software",
        "overall_level": 1,
        "validation_dates": ["4/10/2026"],
        "sunset_date": "4/9/2031",
        "caveat": "When operated in approved mode and installed as described in the Security Policy.",
        "security_level_exceptions": ["Physical security: N/A"],
        "vendor": {
            "name": "SUSE LLC",
            "website_url": "https://www.suse.com/",
            "contact_email": "security@suse.com",
        },
        "related_files": [
            {
                "label": "Security Policy",
                "url": "https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5238.pdf",
            }
        ],
        "validation_history": [
            {"date": "4/10/2026", "type": "Initial", "lab": "Example Lab"}
        ],
        "algorithms": ["AES", "HMAC", "RSA"],
    }
    algorithms_summary = {
        "total_unique_algorithms": 45,
        "total_certificate_algorithm_pairs": 8500,
        "algorithms": {
            "AES": {
                "count": 950,
                "certificates": [5238, 5237, 5236],
            }
        },
    }

    artifacts = generate_text_artifacts(
        metadata,
        sample_module,
        sample_detail,
        algorithms_summary,
    )
    assert "llms-full.txt" in artifacts, "Missing llms-full.txt artifact"
    assert "api/docs.md" in artifacts, "Missing Markdown API docs artifact"
    assert "api/algorithms.json" in artifacts["llms.txt"], "llms.txt should reference algorithms endpoint when available"
    assert 'href="api/docs.md"' in artifacts["index.html"], "Homepage should link to api/docs.md"
    assert "GET api/certificates/{certificate}.json" in artifacts["api/docs.md"], "API docs should include certificate detail endpoint"

    index_payload = build_index_payload(metadata, algorithms_summary)
    assert index_payload["documentation"]["llms_full_txt"] == "/llms-full.txt", "Index payload should advertise llms-full.txt"
    assert index_payload["features"]["markdown_api_docs"] is True, "Index payload should advertise Markdown docs support"

    openapi = generate_openapi_spec(
        [sample_module],
        metadata,
        sample_detail,
        algorithms_summary,
    )
    assert "/api/algorithms.json" in openapi["paths"], "OpenAPI spec should include algorithms endpoint when available"
    assert openapi["components"]["schemas"]["Module"]["properties"]["detail_available"]["type"] == "boolean", "detail_available should be typed as boolean"

    print("✓ Agent-friendly docs generation test passed")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing NIST CMVP Scraper")
    print("=" * 60)
    print()
    
    try:
        test_parse_simple_table()
        test_parse_table_without_thead()
        test_parse_empty_table()
        test_parse_historical_modules_table()
        test_parse_modules_in_process()
        test_parse_certificate_detail_page()
        test_parse_algorithms_from_policy_text()
        test_parse_algorithms_from_legacy_policy_text()
        test_extract_legacy_algorithm_section_prefers_body_over_toc()
        test_parse_algorithms_from_firecrawl_markdown()
        test_build_certificate_fingerprint()
        test_prune_orphan_certificate_details()
        test_generate_agent_docs()
        
        print()
        print("=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
