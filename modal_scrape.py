"""Run the NIST CMVP scraper on Modal.

Usage:
    python -m modal run modal_scrape.py::smoke
    python -m modal run modal_scrape.py::main
    python -m modal run modal_scrape.py::sharded --shard-count 8 --no-use-cache-volume

The full run stores logs and a generated artifact archive in the
``nist-cmvp-api-cache`` Modal Volume.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import modal


APP_NAME = "nist-cmvp-api-scraper"
CACHE_VOLUME_NAME = "nist-cmvp-api-cache"
WORKDIR = "/workspace"
CACHE_DIR = "/cache"


def _ignore_for_modal(path):
    """Keep the Modal image focused on source and checked-in API cache."""
    name = path.name
    if name in {".git", ".github", "venv", "env", "ENV", "__pycache__"}:
        return True
    if name.startswith(".venv"):
        return True
    if name.endswith((".pyc", ".log")):
        return True
    return False


app = modal.App(APP_NAME)
cache_volume = modal.Volume.from_name(CACHE_VOLUME_NAME, create_if_missing=True)

image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install_from_requirements("requirements.txt")
    .add_local_dir(".", WORKDIR, copy=True, ignore=_ignore_for_modal)
    .workdir(WORKDIR)
)


@app.function(image=image, cpu=2, memory=1024, timeout=120)
def modal_smoke() -> dict:
    """Small remote execution check."""
    import os
    import platform

    return {
        "ok": True,
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
    }


def _configure_scraper_environment(
    *,
    algorithm_source: str,
    skip_algorithms: bool,
    full_refresh: bool,
    cert_fetch_concurrency: int,
    pdf_fetch_concurrency: int,
    cert_process_timeout: int,
) -> None:
    """Set scraper environment variables before importing or using scraper.py."""
    import os

    os.environ.update(
        {
            "PYTHONUNBUFFERED": "1",
            "ALGORITHM_SOURCE": algorithm_source,
            "SKIP_ALGORITHMS": "1" if skip_algorithms else "0",
            "FULL_REFRESH": "1" if full_refresh else "0",
            "CERT_FETCH_CONCURRENCY": str(cert_fetch_concurrency),
            "PDF_FETCH_CONCURRENCY": str(pdf_fetch_concurrency),
            "CERT_PROCESS_TIMEOUT": str(cert_process_timeout),
        }
    )


def _sync_cache_to_workdir(*, use_cache_volume: bool, copy_cache: bool = True) -> None:
    """Expose cached API artifacts from the Modal Volume in the working tree."""
    import shutil
    from pathlib import Path

    cache_api = Path(CACHE_DIR) / "api"
    target_api = Path(WORKDIR) / "api"
    if not use_cache_volume or not cache_api.exists():
        return
    if target_api.is_symlink() or target_api.is_file():
        target_api.unlink()
    elif target_api.exists():
        shutil.rmtree(target_api)
    if copy_cache:
        shutil.copytree(cache_api, target_api)
    else:
        target_api.symlink_to(cache_api, target_is_directory=True)


def _empty_previous_outputs() -> dict:
    """Return the scraper's empty previous-output shape."""
    return {
        "metadata": {},
        "modules": {"active": {}, "historical": {}},
        "details": {},
    }


def _artifact_paths_for_run(run_id: str):
    """Return common Modal Volume paths for a run."""
    from pathlib import Path

    run_dir = Path(CACHE_DIR) / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return {
        "run_dir": run_dir,
        "scraper_log": run_dir / "scraper.log",
        "validate_log": run_dir / "validate.log",
        "artifact": run_dir / "artifacts.tar.gz",
    }


def _archive_artifacts(artifact_path) -> None:
    """Archive generated public artifacts into a Modal Volume tarball."""
    import tarfile
    from pathlib import Path

    workdir = Path(WORKDIR)
    if not (workdir / "api").exists():
        return
    with tarfile.open(artifact_path, "w:gz") as archive:
        for relative in ("api", "openapi.json", "llms.txt", "llms-full.txt", "index.html"):
            source = workdir / relative
            if source.exists():
                archive.add(source, arcname=relative)


def _validate_generated_artifacts(*, require_data_quality_pass: bool) -> tuple[int, str]:
    """Run validate_api.py with the same strict flags used by CI."""
    import subprocess
    import sys

    validate_cmd = [
        sys.executable,
        "validate_api.py",
        "--require-current-schema",
        "--forbid-firecrawl-run-source",
    ]
    if require_data_quality_pass:
        validate_cmd.append("--require-data-quality-pass")
    validation = subprocess.run(
        validate_cmd,
        cwd=WORKDIR,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return validation.returncode, validation.stdout


def _load_run_json(run_id: str, relative_path: str) -> dict:
    """Load one run-scoped JSON file from the Modal Volume."""
    import json
    from pathlib import Path

    path = Path(CACHE_DIR) / "runs" / run_id / relative_path
    return json.loads(path.read_text(encoding="utf-8"))


def _write_run_json(
    run_id: str,
    relative_path: str,
    payload: dict,
    *,
    sort_keys: bool = True,
) -> None:
    """Write one run-scoped JSON file to the Modal Volume."""
    import json
    from pathlib import Path

    path = Path(CACHE_DIR) / "runs" / run_id / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=sort_keys), encoding="utf-8")


def _int_keyed_map(mapping: dict) -> dict:
    """Return a copy of a JSON-loaded map with numeric string keys restored."""
    result = {}
    for key, value in (mapping or {}).items():
        try:
            result[int(key)] = value
        except (TypeError, ValueError):
            result[key] = value
    return result


def _load_previous_outputs_for_run(run_id: str) -> dict:
    """Load compacted previous outputs and restore integer certificate keys."""
    previous_outputs = _load_run_json(run_id, "previous_outputs.json")
    modules = previous_outputs.get("modules") or {}
    previous_outputs["modules"] = {
        "active": _int_keyed_map(modules.get("active") or {}),
        "historical": _int_keyed_map(modules.get("historical") or {}),
    }
    previous_outputs["details"] = _int_keyed_map(previous_outputs.get("details") or {})
    return previous_outputs


@app.function(
    image=image,
    volumes={CACHE_DIR: cache_volume},
    cpu=8,
    memory=16_384,
    timeout=7_200,
)
def run_remote_scraper(
    algorithm_source: str = "crawl4ai",
    skip_algorithms: bool = False,
    full_refresh: bool = False,
    cert_fetch_concurrency: int = 16,
    pdf_fetch_concurrency: int = 32,
    cert_process_timeout: int = 900,
    require_data_quality_pass: bool = True,
    use_cache_volume: bool = True,
    update_cache_volume: bool = True,
) -> dict:
    """Run scraper.py and validate_api.py in a Modal container."""
    import os
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    workdir = Path(WORKDIR)
    cache_dir = Path(CACHE_DIR)
    cache_api = cache_dir / "api"
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    paths = _artifact_paths_for_run(run_id)

    _sync_cache_to_workdir(use_cache_volume=use_cache_volume)

    _configure_scraper_environment(
        algorithm_source=algorithm_source,
        skip_algorithms=skip_algorithms,
        full_refresh=full_refresh,
        cert_fetch_concurrency=cert_fetch_concurrency,
        pdf_fetch_concurrency=pdf_fetch_concurrency,
        cert_process_timeout=cert_process_timeout,
    )

    scraper = subprocess.run(
        [sys.executable, "-u", "scraper.py"],
        cwd=workdir,
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    paths["scraper_log"].write_text(scraper.stdout, encoding="utf-8")

    validation_log = ""
    validation_returncode = None
    if scraper.returncode == 0:
        validation_returncode, validation_log = _validate_generated_artifacts(
            require_data_quality_pass=require_data_quality_pass
        )
    else:
        validation_returncode = None

    paths["validate_log"].write_text(validation_log, encoding="utf-8")

    success = scraper.returncode == 0 and validation_returncode == 0

    _archive_artifacts(paths["artifact"])

    if success and update_cache_volume and (workdir / "api").exists():
        if cache_api.exists():
            shutil.rmtree(cache_api)
        shutil.copytree(workdir / "api", cache_api)

    metadata = {}
    data_quality = {}
    for filename, target in (
        ("api/metadata.json", metadata),
        ("api/data-quality.json", data_quality),
    ):
        path = workdir / filename
        if path.exists():
            target.update(json.loads(path.read_text(encoding="utf-8")))

    cache_volume.commit()

    return {
        "ok": success,
        "run_id": run_id,
        "scraper_returncode": scraper.returncode,
        "validation_returncode": validation_returncode,
        "generated_at": metadata.get("generated_at"),
        "algorithm_source": metadata.get("algorithm_source"),
        "total_modules": metadata.get("total_modules"),
        "total_historical_modules": metadata.get("total_historical_modules"),
        "total_modules_in_process": metadata.get("total_modules_in_process"),
        "total_certificate_details": metadata.get("total_certificate_details"),
        "quality_status": (data_quality.get("update_monitor") or {}).get("status"),
        "quality_summary": data_quality.get("summary"),
        "quality_checks": {
            check.get("name"): check.get("status")
            for check in (data_quality.get("update_monitor") or {}).get("checks", [])
            if isinstance(check, dict)
        },
        "artifact": f"{CACHE_VOLUME_NAME}:/runs/{run_id}/artifacts.tar.gz",
        "logs": {
            "scraper": f"{CACHE_VOLUME_NAME}:/runs/{run_id}/scraper.log",
            "validate": f"{CACHE_VOLUME_NAME}:/runs/{run_id}/validate.log",
        },
        "scraper_log_tail": scraper.stdout[-4000:],
        "validation_log_tail": validation_log[-4000:],
    }


@app.function(
    image=image,
    volumes={CACHE_DIR: cache_volume},
    cpu=2,
    memory=4096,
    timeout=1800,
)
def prepare_sharded_run(
    run_id: str,
    algorithm_source: str = "crawl4ai",
    skip_algorithms: bool = False,
    full_refresh: bool = False,
    cert_fetch_concurrency: int = 16,
    pdf_fetch_concurrency: int = 32,
    cert_process_timeout: int = 900,
    use_cache_volume: bool = True,
) -> dict:
    """Scrape module lists once and store the sharded run catalog."""
    import os

    _configure_scraper_environment(
        algorithm_source=algorithm_source,
        skip_algorithms=skip_algorithms,
        full_refresh=full_refresh,
        cert_fetch_concurrency=cert_fetch_concurrency,
        pdf_fetch_concurrency=pdf_fetch_concurrency,
        cert_process_timeout=cert_process_timeout,
    )
    os.chdir(WORKDIR)
    _sync_cache_to_workdir(
        use_cache_volume=use_cache_volume and not full_refresh,
        copy_cache=False,
    )

    import scraper

    scraper.FULL_REFRESH = full_refresh
    scraper.CERT_FETCH_CONCURRENCY = cert_fetch_concurrency
    scraper.PDF_FETCH_CONCURRENCY = pdf_fetch_concurrency
    scraper.CERT_PROCESS_TIMEOUT = cert_process_timeout

    selected_source = scraper.select_algorithm_source(
        algorithm_source,
        skip_algorithms,
        scraper.CMVP_DB_PATH,
        scraper.CRAWL4AI_AVAILABLE,
    )
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    modules = scraper.scrape_all_modules()
    scraper.validate_module_count(modules, "validated modules", min_expected=100)
    historical_modules = scraper.scrape_historical_modules()
    scraper.validate_module_count(historical_modules, "historical modules", min_expected=500)
    modules_in_process = scraper.scrape_modules_in_process()
    scraper.validate_module_count(modules_in_process, "modules in process", min_expected=20)

    modules = scraper.enrich_modules_with_urls(modules)
    historical_modules = scraper.enrich_modules_with_urls(historical_modules)

    previous_outputs = _empty_previous_outputs()
    cache_detail_count = 0
    if not full_refresh:
        previous_outputs = scraper.load_previous_outputs()
        cache_detail_count = len(previous_outputs.get("details", {}))

    catalog = {
        "run_id": run_id,
        "generated_at": generated_at,
        "algorithm_source": selected_source,
        "skip_algorithms": skip_algorithms,
        "full_refresh": full_refresh,
        "modules": modules,
        "historical_modules": historical_modules,
        "modules_in_process": modules_in_process,
    }
    _write_run_json(run_id, "catalog.json", catalog)
    _write_run_json(run_id, "previous_outputs.json", previous_outputs, sort_keys=False)
    cache_volume.commit()

    return {
        "ok": True,
        "run_id": run_id,
        "generated_at": generated_at,
        "algorithm_source": selected_source,
        "total_modules": len(modules),
        "total_historical_modules": len(historical_modules),
        "total_modules_in_process": len(modules_in_process),
        "cache_detail_count": cache_detail_count,
    }


@app.function(
    image=image,
    volumes={CACHE_DIR: cache_volume},
    cpu=8,
    memory=16_384,
    timeout=7_200,
)
def process_certificate_shard(
    run_id: str,
    dataset: str,
    shard_index: int,
    shard_count: int,
    cert_fetch_concurrency: int = 16,
    pdf_fetch_concurrency: int = 32,
    cert_process_timeout: int = 900,
    use_cache_volume: bool = True,
) -> dict:
    """Process one active or historical certificate shard."""
    import asyncio
    import os

    catalog = _load_run_json(run_id, "catalog.json")
    full_refresh = bool(catalog.get("full_refresh"))
    algorithm_source = catalog.get("algorithm_source") or "crawl4ai"
    skip_algorithms = bool(catalog.get("skip_algorithms"))

    _configure_scraper_environment(
        algorithm_source=algorithm_source,
        skip_algorithms=skip_algorithms,
        full_refresh=full_refresh,
        cert_fetch_concurrency=cert_fetch_concurrency,
        pdf_fetch_concurrency=pdf_fetch_concurrency,
        cert_process_timeout=cert_process_timeout,
    )
    os.chdir(WORKDIR)
    _sync_cache_to_workdir(
        use_cache_volume=use_cache_volume and not full_refresh,
        copy_cache=False,
    )

    import scraper

    scraper.FULL_REFRESH = full_refresh
    scraper.CERT_FETCH_CONCURRENCY = cert_fetch_concurrency
    scraper.PDF_FETCH_CONCURRENCY = pdf_fetch_concurrency
    scraper.CERT_PROCESS_TIMEOUT = cert_process_timeout

    key = "modules" if dataset == "active" else "historical_modules"
    records = catalog[key]
    indexed_records = [
        (index, record)
        for index, record in enumerate(records)
        if index % shard_count == shard_index
    ]
    selected_records = [record for _, record in indexed_records]

    previous_outputs = (
        _empty_previous_outputs()
        if full_refresh
        else _load_previous_outputs_for_run(run_id)
    )
    processed_modules, detail_payloads, algorithms_map, stats = asyncio.run(
        scraper.build_certificate_artifacts(
            selected_records,
            dataset,
            catalog["generated_at"],
            algorithm_source,
            previous_outputs,
            {},
        )
    )

    shard_payload = {
        "run_id": run_id,
        "dataset": dataset,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "input_count": len(selected_records),
        "records": [
            {
                "index": original_index,
                "module": processed_module,
            }
            for (original_index, _), processed_module in zip(indexed_records, processed_modules)
        ],
        "detail_payloads": {
            str(cert_number): payload
            for cert_number, payload in detail_payloads.items()
        },
        "algorithms_map": {
            str(cert_number): algorithms
            for cert_number, algorithms in algorithms_map.items()
        },
        "stats": stats,
    }
    shard_path = f"shards/{dataset}-{shard_index:04d}.json"
    _write_run_json(run_id, shard_path, shard_payload)
    cache_volume.commit()

    return {
        "ok": True,
        "run_id": run_id,
        "dataset": dataset,
        "shard_index": shard_index,
        "input_count": len(selected_records),
        "detail_count": len(detail_payloads),
        "algorithm_count": len(algorithms_map),
        "stats": stats,
        "path": f"{CACHE_VOLUME_NAME}:/runs/{run_id}/{shard_path}",
    }


@app.function(
    image=image,
    volumes={CACHE_DIR: cache_volume},
    cpu=4,
    memory=8192,
    timeout=3600,
)
def reduce_sharded_run(
    run_id: str,
    shard_count: int,
    require_data_quality_pass: bool = True,
    use_cache_volume: bool = True,
    update_cache_volume: bool = True,
) -> dict:
    """Merge shard outputs, regenerate public artifacts, and validate."""
    import os
    import shutil
    from pathlib import Path

    catalog = _load_run_json(run_id, "catalog.json")
    full_refresh = bool(catalog.get("full_refresh"))
    algorithm_source = catalog.get("algorithm_source") or "crawl4ai"
    skip_algorithms = bool(catalog.get("skip_algorithms"))

    _configure_scraper_environment(
        algorithm_source=algorithm_source,
        skip_algorithms=skip_algorithms,
        full_refresh=full_refresh,
        cert_fetch_concurrency=16,
        pdf_fetch_concurrency=32,
        cert_process_timeout=900,
    )
    os.chdir(WORKDIR)
    import scraper

    scraper.FULL_REFRESH = full_refresh

    previous_outputs = (
        _empty_previous_outputs()
        if full_refresh
        else _load_previous_outputs_for_run(run_id)
    )

    output_path = Path(WORKDIR) / "api"
    if output_path.is_symlink() or output_path.is_file():
        output_path.unlink()
    elif output_path.exists():
        shutil.rmtree(output_path)

    modules = [None] * len(catalog["modules"])
    historical_modules = [None] * len(catalog["historical_modules"])
    certificate_detail_payloads = {}
    algorithms_map = {}
    active_stats = scraper.new_processing_stats()
    historical_stats = scraper.new_processing_stats()

    for dataset, target_records, target_stats in (
        ("active", modules, active_stats),
        ("historical", historical_modules, historical_stats),
    ):
        for shard_index in range(shard_count):
            shard = _load_run_json(run_id, f"shards/{dataset}-{shard_index:04d}.json")
            for record in shard["records"]:
                target_records[record["index"]] = record["module"]
            certificate_detail_payloads.update(
                {
                    int(cert_number): payload
                    for cert_number, payload in shard["detail_payloads"].items()
                }
            )
            algorithms_map.update(
                {
                    int(cert_number): algorithms
                    for cert_number, algorithms in shard["algorithms_map"].items()
                }
            )
            scraper.add_processing_stats(target_stats, shard["stats"])

    modules = [record or {} for record in modules]
    historical_modules = [record or {} for record in historical_modules]
    modules_in_process = catalog["modules_in_process"]

    extraction_metrics = scraper.build_extraction_metrics(active_stats, historical_stats)
    metadata = {
        "generated_at": catalog["generated_at"],
        "total_modules": len(modules),
        "total_historical_modules": len(historical_modules),
        "total_modules_in_process": len(modules_in_process),
        "total_certificates_with_algorithms": len(algorithms_map),
        "total_certificate_details": len(certificate_detail_payloads),
        "source": scraper.BASE_URL,
        "modules_in_process_source": scraper.MODULES_IN_PROCESS_URL,
        "algorithm_source": algorithm_source,
        "algorithm_cache_version": scraper.ALGORITHM_CACHE_VERSION,
        "algorithm_extraction_schema_version": scraper.ALGORITHM_EXTRACTION_SCHEMA_VERSION,
        "extraction_metrics": extraction_metrics,
        "version": "3.0",
    }

    output_dir = "api"
    scraper.save_json({"metadata": metadata, "modules": modules}, f"{output_dir}/modules.json")
    scraper.save_json({"metadata": metadata, "modules": historical_modules}, f"{output_dir}/historical-modules.json")
    scraper.save_json({"metadata": metadata, "modules_in_process": modules_in_process}, f"{output_dir}/modules-in-process.json")

    for cert_number, certificate_payload in certificate_detail_payloads.items():
        detail_response = {
            "metadata": {
                "generated_at": catalog["generated_at"],
                "dataset": certificate_payload.get("dataset", "active"),
                "source": certificate_payload.get("nist_page_url", scraper.get_certificate_detail_url(cert_number)),
            },
            "certificate": certificate_payload,
        }
        scraper.save_json(detail_response, f"{output_dir}/certificates/{cert_number}.json")

    current_cert_numbers = {
        cert_number
        for cert_number in (
            scraper.parse_certificate_number(module) for module in modules + historical_modules
        )
        if cert_number is not None
    }
    removed_orphans = scraper.prune_orphan_certificate_details(current_cert_numbers)

    certificate_index_data = scraper.build_certificate_index_payload(
        metadata,
        modules,
        historical_modules,
        certificate_detail_payloads,
    )
    scraper.save_json(certificate_index_data, f"{output_dir}/certificates/index.json")

    for path, search_index_payload in scraper.build_search_index_payloads(metadata, certificate_index_data).items():
        scraper.save_json(search_index_payload, path)

    data_quality_report = scraper.build_data_quality_report(
        metadata,
        modules,
        historical_modules,
        certificate_detail_payloads,
        previous_outputs,
        active_stats,
        historical_stats,
    )
    scraper.save_json(data_quality_report, f"{output_dir}/data-quality.json")
    scraper.save_json(scraper.build_examples_payload(metadata), f"{output_dir}/examples.json")

    algorithms_summary = None
    if algorithms_map:
        algorithms_summary = scraper.create_algorithms_summary(algorithms_map)
        algorithms_summary["metadata"] = {
            "generated_at": metadata["generated_at"],
            "total_certificates_processed": len(algorithms_map),
            "source": algorithm_source,
            "algorithm_source": algorithm_source,
            "algorithm_cache_version": scraper.ALGORITHM_CACHE_VERSION,
            "algorithm_extraction_schema_version": scraper.ALGORITHM_EXTRACTION_SCHEMA_VERSION,
            "extraction_metrics": extraction_metrics["combined"],
        }
        scraper.save_json(algorithms_summary, f"{output_dir}/algorithms.json")
    else:
        algorithms_path = Path(output_dir) / "algorithms.json"
        if algorithms_path.exists():
            algorithms_path.unlink()

    scraper.save_json(metadata, f"{output_dir}/metadata.json")
    scraper.save_json(scraper.build_index_payload(metadata, algorithms_summary), f"{output_dir}/index.json")

    sample_certificate_detail = next(iter(certificate_detail_payloads.values()), None)
    openapi_spec = scraper.generate_openapi_spec(
        modules,
        metadata,
        sample_certificate_detail,
        algorithms_summary,
    )
    scraper.save_json(openapi_spec, "openapi.json")

    for path, content in scraper.generate_text_artifacts(
        metadata,
        modules[0] if modules else None,
        sample_certificate_detail,
        algorithms_summary,
    ).items():
        scraper.save_text(content, path)

    schema_artifacts = scraper.generate_json_schema_artifacts(algorithms_summary)
    for path, schema in schema_artifacts.items():
        scraper.save_json(schema, path)

    validation_returncode, validation_log = _validate_generated_artifacts(
        require_data_quality_pass=require_data_quality_pass
    )
    paths = _artifact_paths_for_run(run_id)
    paths["validate_log"].write_text(validation_log, encoding="utf-8")
    _archive_artifacts(paths["artifact"])

    success = validation_returncode == 0

    cache_api = Path(CACHE_DIR) / "api"
    if success and update_cache_volume and (Path(WORKDIR) / "api").exists():
        if cache_api.exists():
            shutil.rmtree(cache_api)
        shutil.copytree(Path(WORKDIR) / "api", cache_api)

    cache_volume.commit()

    return {
        "ok": success,
        "run_id": run_id,
        "generated_at": metadata.get("generated_at"),
        "algorithm_source": metadata.get("algorithm_source"),
        "total_modules": metadata.get("total_modules"),
        "total_historical_modules": metadata.get("total_historical_modules"),
        "total_modules_in_process": metadata.get("total_modules_in_process"),
        "total_certificate_details": metadata.get("total_certificate_details"),
        "removed_orphans": removed_orphans,
        "quality_status": (data_quality_report.get("update_monitor") or {}).get("status"),
        "quality_summary": data_quality_report.get("summary"),
        "quality_checks": {
            check.get("name"): check.get("status")
            for check in (data_quality_report.get("update_monitor") or {}).get("checks", [])
            if isinstance(check, dict)
        },
        "active_stats": active_stats,
        "historical_stats": historical_stats,
        "validation_returncode": validation_returncode,
        "validation_log_tail": validation_log[-4000:],
        "artifact": f"{CACHE_VOLUME_NAME}:/runs/{run_id}/artifacts.tar.gz",
        "logs": {
            "validate": f"{CACHE_VOLUME_NAME}:/runs/{run_id}/validate.log",
        },
    }


@app.local_entrypoint()
def main(
    algorithm_source: str = "crawl4ai",
    skip_algorithms: bool = False,
    full_refresh: bool = False,
    cert_fetch_concurrency: int = 16,
    pdf_fetch_concurrency: int = 32,
    cert_process_timeout: int = 900,
    require_data_quality_pass: bool = True,
    use_cache_volume: bool = True,
    update_cache_volume: bool = True,
) -> None:
    """Run the scraper remotely and print a JSON summary."""
    result = run_remote_scraper.remote(
        algorithm_source=algorithm_source,
        skip_algorithms=skip_algorithms,
        full_refresh=full_refresh,
        cert_fetch_concurrency=cert_fetch_concurrency,
        pdf_fetch_concurrency=pdf_fetch_concurrency,
        cert_process_timeout=cert_process_timeout,
        require_data_quality_pass=require_data_quality_pass,
        use_cache_volume=use_cache_volume,
        update_cache_volume=update_cache_volume,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result.get("ok"):
        raise SystemExit(1)


@app.local_entrypoint(name="smoke")
def smoke() -> None:
    """Run a cheap remote Modal smoke test."""
    print(json.dumps(modal_smoke.remote(), indent=2, sort_keys=True))


@app.local_entrypoint(name="sharded")
def sharded(
    shard_count: int = 8,
    algorithm_source: str = "crawl4ai",
    skip_algorithms: bool = False,
    full_refresh: bool = False,
    cert_fetch_concurrency: int = 16,
    pdf_fetch_concurrency: int = 32,
    cert_process_timeout: int = 900,
    require_data_quality_pass: bool = True,
    use_cache_volume: bool = True,
    update_cache_volume: bool = True,
) -> None:
    """Run the scraper as parallel active/historical shards on Modal."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prepared = prepare_sharded_run.remote(
        run_id=run_id,
        algorithm_source=algorithm_source,
        skip_algorithms=skip_algorithms,
        full_refresh=full_refresh,
        cert_fetch_concurrency=cert_fetch_concurrency,
        pdf_fetch_concurrency=pdf_fetch_concurrency,
        cert_process_timeout=cert_process_timeout,
        use_cache_volume=use_cache_volume,
    )
    print(json.dumps({"prepared": prepared}, indent=2, sort_keys=True))

    shard_inputs = [
        (
            run_id,
            dataset,
            shard_index,
            shard_count,
            cert_fetch_concurrency,
            pdf_fetch_concurrency,
            cert_process_timeout,
            use_cache_volume,
        )
        for dataset in ("active", "historical")
        for shard_index in range(shard_count)
    ]
    shard_results = list(
        process_certificate_shard.starmap(
            shard_inputs,
            order_outputs=False,
        )
    )
    print(json.dumps({"shards": shard_results}, indent=2, sort_keys=True))

    result = reduce_sharded_run.remote(
        run_id=run_id,
        shard_count=shard_count,
        require_data_quality_pass=require_data_quality_pass,
        use_cache_volume=use_cache_volume,
        update_cache_volume=update_cache_volume,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result.get("ok"):
        raise SystemExit(1)
