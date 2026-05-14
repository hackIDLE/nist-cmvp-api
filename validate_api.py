#!/usr/bin/env python3
"""Validate generated static API artifacts for internal consistency."""

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


REQUIRED_TOP_LEVEL_FILES = (
    "api/modules.json",
    "api/historical-modules.json",
    "api/modules-in-process.json",
    "api/metadata.json",
    "api/index.json",
    "api/certificates/index.json",
    "openapi.json",
    "llms.txt",
    "llms-full.txt",
    "api/docs.md",
    "index.html",
)

DETAIL_REQUIRED_FIELDS = (
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
)

CURRENT_SCHEMA_DETAIL_FIELDS = (
    "software_versions",
    "hardware_versions",
    "firmware_versions",
    "algorithm_extraction",
)

ALGORITHM_EXTRACTION_REQUIRED_FIELDS = (
    "schema_version",
    "status",
    "configured_source",
    "source",
    "source_url",
    "cached",
    "fallback_used",
    "cache_version",
    "algorithm_count",
    "detailed_algorithm_count",
)

ALGORITHM_EXTRACTION_STATUSES = {"parsed", "cached", "miss", "skipped"}

JSON_SCHEMA_FILES = (
    "api/schemas/index.schema.json",
    "api/schemas/metadata.schema.json",
    "api/schemas/module.schema.json",
    "api/schemas/module-in-process.schema.json",
    "api/schemas/modules.schema.json",
    "api/schemas/historical-modules.schema.json",
    "api/schemas/modules-in-process.schema.json",
    "api/schemas/certificate-index.schema.json",
    "api/schemas/certificate-detail.schema.json",
)


def load_json(path: Path, errors: List[str]) -> Optional[Dict]:
    """Load a JSON file and append a validation error on failure."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        errors.append(f"{path}: failed to load JSON: {exc}")
        return None

    if not isinstance(payload, dict):
        errors.append(f"{path}: top-level JSON value must be an object")
        return None
    return payload


def parse_certificate_number(record: Dict) -> Optional[int]:
    """Return a numeric certificate number from a module or detail record."""
    for key in ("Certificate Number", "certificate_number"):
        value = str(record.get(key, "")).strip()
        if value.isdigit():
            return int(value)
    return None


def add_error(errors: List[str], condition: bool, message: str) -> None:
    """Append message when condition is false."""
    if not condition:
        errors.append(message)


def count_certificate_algorithm_pairs(cert_algorithms: Dict[int, List[str]]) -> int:
    """Count certificate/algorithm pairs from module rows."""
    return sum(len(algorithms) for algorithms in cert_algorithms.values())


def build_expected_algorithm_index(cert_algorithms: Dict[int, List[str]]) -> Dict[str, Set[int]]:
    """Build algorithm -> certificate set from module rows."""
    expected: Dict[str, Set[int]] = {}
    for cert_number, algorithms in cert_algorithms.items():
        for algorithm in algorithms:
            expected.setdefault(algorithm, set()).add(cert_number)
    return expected


def validate_algorithm_extraction(
    record: Dict,
    label: str,
    require_current_schema: bool,
    errors: List[str],
) -> None:
    """Validate an optional per-certificate algorithm_extraction object."""
    extraction = record.get("algorithm_extraction")
    if extraction is None:
        if require_current_schema:
            errors.append(f"{label}: missing algorithm_extraction")
        return

    if not isinstance(extraction, dict):
        errors.append(f"{label}: algorithm_extraction must be an object")
        return

    for field in ALGORITHM_EXTRACTION_REQUIRED_FIELDS:
        add_error(errors, field in extraction, f"{label}: algorithm_extraction missing {field}")

    status = extraction.get("status")
    add_error(
        errors,
        status in ALGORITHM_EXTRACTION_STATUSES,
        f"{label}: invalid algorithm_extraction.status {status!r}",
    )

    algorithms = record.get("algorithms") or []
    detailed = record.get("algorithms_detailed") or []
    if isinstance(extraction.get("algorithm_count"), int):
        add_error(
            errors,
            extraction["algorithm_count"] == len(algorithms),
            f"{label}: algorithm_extraction.algorithm_count does not match algorithms length",
        )
    if isinstance(extraction.get("detailed_algorithm_count"), int):
        add_error(
            errors,
            extraction["detailed_algorithm_count"] == len(detailed),
            f"{label}: algorithm_extraction.detailed_algorithm_count does not match algorithms_detailed length",
        )


def validate_module_rows(
    rows: Iterable[Dict],
    dataset: str,
    errors: List[str],
    require_current_schema: bool,
) -> Tuple[Dict[int, str], Dict[int, List[str]]]:
    """Validate active or historical module rows and return cert metadata."""
    cert_datasets: Dict[int, str] = {}
    cert_algorithms: Dict[int, List[str]] = {}

    for index, row in enumerate(rows):
        label = f"{dataset} modules[{index}]"
        cert_number = parse_certificate_number(row)
        if cert_number is None:
            errors.append(f"{label}: missing numeric Certificate Number")
            continue

        if cert_number in cert_datasets:
            errors.append(f"{label}: duplicate certificate {cert_number}")
        cert_datasets[cert_number] = dataset

        for field in ("Vendor Name", "Module Name"):
            add_error(errors, field in row, f"{label}: missing {field}")
        for field in ("security_policy_url", "certificate_detail_url"):
            add_error(errors, bool(row.get(field)), f"{label}: missing {field}")
        add_error(errors, row.get("detail_available") is True, f"{label}: detail_available is not true")

        algorithms = row.get("algorithms") or []
        if algorithms:
            add_error(errors, isinstance(algorithms, list), f"{label}: algorithms must be a list")
            cert_algorithms[cert_number] = algorithms
        validate_algorithm_extraction(row, label, require_current_schema, errors)

    return cert_datasets, cert_algorithms


def validate_certificate_details(
    detail_dir: Path,
    expected_datasets: Dict[int, str],
    expected_algorithms: Dict[int, List[str]],
    errors: List[str],
    require_current_schema: bool,
) -> None:
    """Validate per-certificate detail files."""
    detail_files = sorted(detail_dir.glob("*.json"))
    found_certificates: Set[int] = set()

    for filepath in detail_files:
        label = str(filepath)
        if filepath.name == "index.json":
            continue
        if not filepath.stem.isdigit():
            errors.append(f"{label}: certificate detail filename must be numeric")
            continue

        file_cert_number = int(filepath.stem)
        payload = load_json(filepath, errors)
        if payload is None:
            continue

        metadata = payload.get("metadata")
        certificate = payload.get("certificate")
        add_error(errors, isinstance(metadata, dict), f"{label}: metadata must be an object")
        add_error(errors, isinstance(certificate, dict), f"{label}: certificate must be an object")
        if not isinstance(certificate, dict):
            continue

        cert_number = parse_certificate_number(certificate)
        add_error(errors, cert_number == file_cert_number, f"{label}: certificate_number does not match filename")
        if cert_number is None:
            continue

        found_certificates.add(cert_number)
        expected_dataset = expected_datasets.get(cert_number)
        add_error(errors, expected_dataset is not None, f"{label}: certificate is not in active or historical modules")
        add_error(errors, certificate.get("dataset") == expected_dataset, f"{label}: dataset does not match module list")

        for field in DETAIL_REQUIRED_FIELDS:
            add_error(errors, field in certificate, f"{label}: certificate missing {field}")
        if require_current_schema:
            for field in CURRENT_SCHEMA_DETAIL_FIELDS:
                add_error(errors, field in certificate, f"{label}: certificate missing current schema field {field}")

        add_error(errors, isinstance(certificate.get("related_files"), list), f"{label}: related_files must be a list")
        add_error(errors, isinstance(certificate.get("validation_history"), list), f"{label}: validation_history must be a list")
        add_error(errors, isinstance(certificate.get("vendor"), dict), f"{label}: vendor must be an object")

        expected_detail_algorithms = expected_algorithms.get(cert_number, [])
        actual_detail_algorithms = certificate.get("algorithms") or []
        add_error(
            errors,
            actual_detail_algorithms == expected_detail_algorithms,
            f"{label}: detail algorithms do not match module row algorithms",
        )
        validate_algorithm_extraction(certificate, label, require_current_schema, errors)

    missing_details = sorted(set(expected_datasets) - found_certificates)
    orphan_details = sorted(found_certificates - set(expected_datasets))
    if missing_details:
        errors.append(f"api/certificates: missing detail files for {len(missing_details)} certificates; first={missing_details[:5]}")
    if orphan_details:
        errors.append(f"api/certificates: found {len(orphan_details)} orphan detail files; first={orphan_details[:5]}")


def validate_certificate_index(
    root: Path,
    metadata: Dict,
    expected_datasets: Dict[int, str],
    expected_algorithms: Dict[int, List[str]],
    errors: List[str],
) -> None:
    """Validate api/certificates/index.json against module rows and detail paths."""
    payload = load_json(root / "api" / "certificates" / "index.json", errors)
    if payload is None:
        return

    add_error(errors, payload.get("metadata") == metadata, "api/certificates/index.json: embedded metadata does not match api/metadata.json")
    add_error(errors, payload.get("total_certificates") == len(expected_datasets), "api/certificates/index.json: total_certificates mismatch")

    certificate_paths = payload.get("certificate_paths")
    certificates = payload.get("certificates")
    add_error(errors, isinstance(certificate_paths, dict), "api/certificates/index.json: certificate_paths must be an object")
    add_error(errors, isinstance(certificates, list), "api/certificates/index.json: certificates must be a list")
    if not isinstance(certificate_paths, dict) or not isinstance(certificates, list):
        return

    found_certificates: Set[int] = set()
    for entry_index, entry in enumerate(certificates):
        label = f"api/certificates/index.json: certificates[{entry_index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label}: entry must be an object")
            continue

        cert_number = parse_certificate_number(entry)
        if cert_number is None:
            errors.append(f"{label}: missing numeric certificate_number")
            continue
        found_certificates.add(cert_number)

        expected_path = f"/api/certificates/{cert_number}.json"
        add_error(errors, certificate_paths.get(str(cert_number)) == expected_path, f"{label}: certificate_paths entry mismatch")
        add_error(errors, entry.get("path") == expected_path, f"{label}: path mismatch")
        add_error(errors, entry.get("dataset") == expected_datasets.get(cert_number), f"{label}: dataset mismatch")
        add_error(errors, entry.get("detail_available") is True, f"{label}: detail_available is not true")

        algorithms = entry.get("algorithms") or []
        add_error(errors, isinstance(algorithms, list), f"{label}: algorithms must be a list")
        if isinstance(algorithms, list):
            add_error(errors, algorithms == expected_algorithms.get(cert_number, []), f"{label}: algorithms mismatch")
            add_error(errors, entry.get("algorithm_count") == len(algorithms), f"{label}: algorithm_count mismatch")

    expected_certificates = set(expected_datasets)
    add_error(errors, found_certificates == expected_certificates, "api/certificates/index.json: certificate set mismatch")
    add_error(errors, set(certificate_paths) == {str(cert) for cert in expected_certificates}, "api/certificates/index.json: certificate_paths keys mismatch")


def validate_algorithms_summary(
    root: Path,
    metadata: Dict,
    expected_cert_algorithms: Dict[int, List[str]],
    errors: List[str],
) -> None:
    """Validate api/algorithms.json against module row algorithm fields."""
    algorithms_path = root / "api" / "algorithms.json"
    expected_total = metadata.get("total_certificates_with_algorithms", 0)

    if expected_total == 0:
        add_error(errors, not algorithms_path.exists(), "api/algorithms.json exists despite zero algorithm coverage")
        return

    summary = load_json(algorithms_path, errors)
    if summary is None:
        return

    algorithms = summary.get("algorithms")
    add_error(errors, isinstance(algorithms, dict), "api/algorithms.json: algorithms must be an object")
    if not isinstance(algorithms, dict):
        return

    expected_index = build_expected_algorithm_index(expected_cert_algorithms)
    add_error(errors, summary.get("total_unique_algorithms") == len(expected_index), "api/algorithms.json: total_unique_algorithms mismatch")
    add_error(
        errors,
        summary.get("total_certificate_algorithm_pairs") == count_certificate_algorithm_pairs(expected_cert_algorithms),
        "api/algorithms.json: total_certificate_algorithm_pairs mismatch",
    )
    add_error(errors, expected_total == len(expected_cert_algorithms), "metadata: total_certificates_with_algorithms mismatch")

    for algorithm, expected_certs in expected_index.items():
        entry = algorithms.get(algorithm)
        if not isinstance(entry, dict):
            errors.append(f"api/algorithms.json: missing algorithm {algorithm}")
            continue
        certs = entry.get("certificates")
        add_error(errors, isinstance(certs, list), f"api/algorithms.json: {algorithm}.certificates must be a list")
        if not isinstance(certs, list):
            continue
        add_error(errors, entry.get("count") == len(certs), f"api/algorithms.json: {algorithm}.count mismatch")
        add_error(errors, len(certs) == len(set(certs)), f"api/algorithms.json: {algorithm}.certificates has duplicates")
        add_error(errors, set(certs) == expected_certs, f"api/algorithms.json: {algorithm}.certificates mismatch")

    extra_algorithms = sorted(set(algorithms) - set(expected_index))
    if extra_algorithms:
        errors.append(f"api/algorithms.json: unexpected algorithms present: {extra_algorithms[:5]}")


def validate_docs_and_index(
    root: Path,
    metadata: Dict,
    has_algorithms: bool,
    errors: List[str],
    require_current_schema: bool,
) -> None:
    """Validate API index, OpenAPI, and docs artifacts at a structural level."""
    index = load_json(root / "api" / "index.json", errors)
    if index:
        for key in (
            "total_modules",
            "total_historical_modules",
            "total_modules_in_process",
            "total_certificates_with_algorithms",
            "total_certificate_details",
        ):
            add_error(errors, index.get(key) == metadata.get(key), f"api/index.json: {key} mismatch")
        endpoints = index.get("endpoints") or {}
        add_error(errors, isinstance(endpoints, dict), "api/index.json: endpoints must be an object")
        if isinstance(endpoints, dict):
            add_error(errors, ("algorithms" in endpoints) == has_algorithms, "api/index.json: algorithms endpoint presence mismatch")
            add_error(errors, endpoints.get("certificate_index") == "/api/certificates/index.json", "api/index.json: missing certificate_index endpoint")
        features = index.get("features") or {}
        if require_current_schema and isinstance(features, dict):
            add_error(errors, features.get("algorithm_extraction_provenance") is True, "api/index.json: missing algorithm_extraction_provenance feature")
            add_error(errors, features.get("extraction_metrics") is True, "api/index.json: missing extraction_metrics feature")
            add_error(errors, features.get("json_schemas") is True, "api/index.json: missing json_schemas feature")
            add_error(errors, features.get("certificate_index") is True, "api/index.json: missing certificate_index feature")
            schemas = index.get("schemas")
            add_error(errors, isinstance(schemas, dict), "api/index.json: schemas must be an object")

    openapi = load_json(root / "openapi.json", errors)
    if openapi:
        paths = openapi.get("paths") or {}
        for path in (
            "/api/index.json",
            "/api/metadata.json",
            "/api/modules.json",
            "/api/historical-modules.json",
            "/api/modules-in-process.json",
            "/api/certificates/index.json",
            "/api/certificates/{certificate}.json",
        ):
            add_error(errors, path in paths, f"openapi.json: missing path {path}")
        add_error(errors, ("/api/algorithms.json" in paths) == has_algorithms, "openapi.json: algorithms path presence mismatch")

    for doc_path, required_text in (
        ("README.md", "certificates/{certificate}.json"),
        ("llms.txt", "api/metadata.json"),
        ("llms-full.txt", "GET api/certificates/index.json"),
        ("api/docs.md", "GET api/certificates/index.json"),
        ("index.html", "api/certificates/index.json"),
    ):
        path = root / doc_path
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            errors.append(f"{doc_path}: failed to read: {exc}")
            continue
        add_error(errors, bool(content.strip()), f"{doc_path}: empty documentation file")
        add_error(errors, required_text in content, f"{doc_path}: missing expected text {required_text!r}")
        if require_current_schema and doc_path in {"llms.txt", "api/docs.md", "index.html"}:
            add_error(errors, "api/schemas/index.schema.json" in content, f"{doc_path}: missing JSON Schema link")

    if require_current_schema:
        expected_schema_files = list(JSON_SCHEMA_FILES)
        if has_algorithms:
            expected_schema_files.append("api/schemas/algorithms.schema.json")
        for relative_path in expected_schema_files:
            schema = load_json(root / relative_path, errors)
            if schema:
                add_error(errors, schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema", f"{relative_path}: missing JSON Schema draft marker")
                add_error(errors, bool(schema.get("$id")), f"{relative_path}: missing $id")
                add_error(errors, bool(schema.get("title")), f"{relative_path}: missing title")
        if not has_algorithms:
            add_error(errors, not (root / "api/schemas/algorithms.schema.json").exists(), "api/schemas/algorithms.schema.json exists despite zero algorithm coverage")


def validate_api(
    root: Path = Path("."),
    require_current_schema: bool = False,
    forbid_firecrawl_run_source: bool = False,
) -> List[str]:
    """Return a list of validation errors for generated API artifacts."""
    errors: List[str] = []
    root = root.resolve()

    for relative_path in REQUIRED_TOP_LEVEL_FILES:
        add_error(errors, (root / relative_path).exists(), f"{relative_path}: missing required artifact")

    metadata = load_json(root / "api" / "metadata.json", errors)
    modules_payload = load_json(root / "api" / "modules.json", errors)
    historical_payload = load_json(root / "api" / "historical-modules.json", errors)
    in_process_payload = load_json(root / "api" / "modules-in-process.json", errors)
    if not all(isinstance(payload, dict) for payload in (metadata, modules_payload, historical_payload, in_process_payload)):
        return errors

    assert metadata is not None and modules_payload is not None and historical_payload is not None and in_process_payload is not None

    for label, payload in (
        ("api/modules.json", modules_payload),
        ("api/historical-modules.json", historical_payload),
        ("api/modules-in-process.json", in_process_payload),
    ):
        add_error(errors, payload.get("metadata") == metadata, f"{label}: embedded metadata does not match api/metadata.json")

    modules = modules_payload.get("modules")
    historical_modules = historical_payload.get("modules")
    modules_in_process = in_process_payload.get("modules_in_process")
    add_error(errors, isinstance(modules, list), "api/modules.json: modules must be a list")
    add_error(errors, isinstance(historical_modules, list), "api/historical-modules.json: modules must be a list")
    add_error(errors, isinstance(modules_in_process, list), "api/modules-in-process.json: modules_in_process must be a list")
    if not isinstance(modules, list) or not isinstance(historical_modules, list) or not isinstance(modules_in_process, list):
        return errors

    add_error(errors, metadata.get("total_modules") == len(modules), "metadata: total_modules mismatch")
    add_error(errors, metadata.get("total_historical_modules") == len(historical_modules), "metadata: total_historical_modules mismatch")
    add_error(errors, metadata.get("total_modules_in_process") == len(modules_in_process), "metadata: total_modules_in_process mismatch")

    active_datasets, active_algorithms = validate_module_rows(modules, "active", errors, require_current_schema)
    historical_datasets, historical_algorithms = validate_module_rows(historical_modules, "historical", errors, require_current_schema)
    overlapping_certs = sorted(set(active_datasets) & set(historical_datasets))
    if overlapping_certs:
        errors.append(f"active/historical modules: duplicate certificate numbers across datasets: {overlapping_certs[:5]}")

    expected_datasets = {**active_datasets, **historical_datasets}
    expected_algorithms = {**active_algorithms, **historical_algorithms}
    add_error(errors, metadata.get("total_certificate_details") == len(expected_datasets), "metadata: total_certificate_details mismatch")

    if require_current_schema:
        add_error(errors, "algorithm_extraction_schema_version" in metadata, "metadata: missing algorithm_extraction_schema_version")
        add_error(errors, "extraction_metrics" in metadata, "metadata: missing extraction_metrics")

    if forbid_firecrawl_run_source:
        add_error(errors, metadata.get("algorithm_source") != "firecrawl", "metadata: algorithm_source must not be firecrawl")

    validate_certificate_details(
        root / "api" / "certificates",
        expected_datasets,
        expected_algorithms,
        errors,
        require_current_schema,
    )
    validate_certificate_index(root, metadata, expected_datasets, expected_algorithms, errors)
    validate_algorithms_summary(root, metadata, expected_algorithms, errors)
    validate_docs_and_index(
        root,
        metadata,
        bool(expected_algorithms),
        errors,
        require_current_schema,
    )

    if forbid_firecrawl_run_source and metadata.get("total_certificates_with_algorithms", 0):
        algorithms_metadata = load_json(root / "api" / "algorithms.json", errors)
        if algorithms_metadata:
            nested_metadata = algorithms_metadata.get("metadata") or {}
            add_error(errors, nested_metadata.get("source") != "firecrawl", "api/algorithms.json: metadata.source must not be firecrawl")
            add_error(errors, nested_metadata.get("algorithm_source") != "firecrawl", "api/algorithms.json: metadata.algorithm_source must not be firecrawl")

    return errors


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root containing generated API artifacts")
    parser.add_argument(
        "--require-current-schema",
        action="store_true",
        help="Require fields generated by the current scraper schema, including extraction provenance",
    )
    parser.add_argument(
        "--forbid-firecrawl-run-source",
        action="store_true",
        help="Fail if the current run metadata says algorithm extraction used Firecrawl",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)
    errors = validate_api(
        Path(args.root),
        require_current_schema=args.require_current_schema,
        forbid_firecrawl_run_source=args.forbid_firecrawl_run_source,
    )
    if errors:
        print("API artifact validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("API artifact validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
