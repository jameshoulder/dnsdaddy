#!/usr/bin/env python3
"""Offline Trivy/KEV correlation and public-register validation (Python 3.12+).

No DNS Daddy runtime data or credentials are read. The only network operation is
an explicitly requested download of the fixed public CISA feed. Exit codes:
0 assessment/validation completed, 1 KEV matches need triage, 2 unavailable/invalid.
A successful correlation is not a vulnerability-free or compliance assertion.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 32 * 1024 * 1024
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def text(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"missing/invalid {label}")
    return value


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode(raw: bytes) -> dict[str, Any]:
    require(len(raw) <= MAX_BYTES, "input exceeds size limit")
    def invalid_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")
    result = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    require(isinstance(result, dict), "expected a JSON object")
    return result


def load(path: Path) -> tuple[dict[str, Any], str]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    return decode(raw), hashlib.sha256(raw).hexdigest()


def timestamp(value: Any, label: str) -> datetime:
    parsed = datetime.fromisoformat(text(value, label).replace("Z", "+00:00"))
    require(parsed.tzinfo is not None, f"{label} must contain a timezone")
    return parsed.astimezone(timezone.utc)


def fresh(value: Any, label: str, now: datetime, days: int) -> None:
    age = now - timestamp(value, label)
    require(timedelta(minutes=-5) <= age <= timedelta(days=days), f"{label} is stale or in the future")


def correlate(scan: dict[str, Any], kev: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Correlate exact CVE IDs/explicit vendor aliases; never infer applicability."""
    require(scan.get("SchemaVersion") == 2, "unsupported Trivy SchemaVersion")
    fresh(scan.get("CreatedAt"), "scan CreatedAt", now, 2)
    fresh(kev.get("dateReleased"), "KEV dateReleased", now, 14)
    catalogue_version = text(kev.get("catalogVersion"), "KEV catalogVersion")
    entries = kev.get("vulnerabilities")
    require(isinstance(entries, list) and len(entries) > 0, "empty/invalid KEV catalogue")
    require(type(kev.get("count")) is int and kev["count"] == len(entries), "KEV count mismatch")
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        require(isinstance(entry, dict), "invalid KEV entry")
        cve = text(entry.get("cveID"), "KEV cveID")
        require(CVE.fullmatch(cve) is not None and cve not in index, "invalid/duplicate KEV CVE")
        date.fromisoformat(text(entry.get("dateAdded"), "KEV dateAdded"))
        text(entry.get("requiredAction"), "KEV requiredAction")
        index[cve] = entry

    results = scan.get("Results")
    require(isinstance(results, list) and len(results) > 0, "no scanned targets")
    require(any(isinstance(r, dict) and r.get("Type") in {"gomod", "gobinary"} for r in results),
            "no Go dependency/binary target: this is not evidence for DNS Daddy")
    findings = []
    targets = []
    for result in results:
        require(isinstance(result, dict), "invalid Trivy result")
        target = text(result.get("Target"), "Trivy target")
        targets.append({"target": target, "type": text(result.get("Type"), "Trivy target type")})
        vulnerabilities = result.get("Vulnerabilities")
        # Trivy omits this field (or emits null) when there are no findings.
        if vulnerabilities is None:
            vulnerabilities = []
        require(isinstance(vulnerabilities, list), "invalid Trivy vulnerability list")
        for vulnerability in vulnerabilities:
            require(isinstance(vulnerability, dict), "invalid Trivy vulnerability")
            identifier = text(vulnerability.get("VulnerabilityID"), "vulnerability ID")
            aliases = vulnerability.get("VendorIDs") or []
            require(isinstance(aliases, list) and all(isinstance(a, str) for a in aliases), "invalid VendorIDs")
            cves = sorted({v for v in [identifier, *aliases] if CVE.fullmatch(v)})
            matches = [index[cve] for cve in cves if cve in index]
            fixed = vulnerability.get("FixedVersion") or ""
            require(isinstance(fixed, str), "invalid FixedVersion")
            findings.append({
                "id": identifier,
                "target": target,
                "package": text(vulnerability.get("PkgName"), "package name"),
                "installed_version": text(vulnerability.get("InstalledVersion"), "installed version"),
                "fixed_version": fixed,
                "severity": vulnerability.get("Severity") or "UNKNOWN",
                "cve_aliases": cves,
                "kev_status": "listed" if matches else ("not_listed" if cves else "no_cve_alias"),
                "kev_matches": [{k: entry.get(k) for k in ("cveID", "dateAdded", "dueDate", "requiredAction")}
                                for entry in matches],
                "applicability": "requires_triage",
            })
    return {
        "schema_version": 1,
        "assessment": "completed_for_supplied_inputs",
        "generated_at": now.isoformat(),
        "scan_created_at": scan["CreatedAt"],
        "kev_catalogue_version": catalogue_version,
        "kev_released_at": kev["dateReleased"],
        "targets": targets,
        "findings": findings,
        "kev_match_count": sum(f["kev_status"] == "listed" for f in findings),
        "limits": [
            "Not listed in KEV does not mean not exploited or not vulnerable.",
            "Package matches require reachability, configuration and version triage.",
            "Only the supplied scan is covered; source scanning does not cover the deployed host or image.",
            "Fresh timestamps and input hashes do not authenticate a scan or prove scanner database freshness.",
            "No finding is automatically suppressed because it has no fix or a low severity.",
        ],
    }


def validate_register(data: dict[str, Any]) -> None:
    require(data.get("schema_version") == 1, "unsupported register version")
    require(data.get("inventory_status") in {"not_assessed", "partial", "reviewed"}, "invalid inventory status")
    text(data.get("scope"), "register scope")
    date.fromisoformat(text(data.get("updated"), "register updated date"))
    records = data.get("vulnerabilities")
    require(isinstance(records, list), "invalid register records")
    if data["inventory_status"] == "reviewed":
        require(bool(data.get("assessment_evidence")), "reviewed inventory needs assessment evidence")
    seen = set()
    for record in records:
        require(isinstance(record, dict), "invalid register entry")
        identifier = text(record.get("id"), "register id")
        require(identifier not in seen, "duplicate register id")
        seen.add(identifier)
        require(record.get("public") is True, "embargoed records do not belong in the public register")
        for field in ("summary", "owner", "affected_versions", "mitigation", "evidence"):
            text(record.get(field), field)
        state = record.get("status")
        require(state in {"investigating", "affected", "fixed", "not_affected"}, "invalid vulnerability status")
        require(record.get("kev_status") in {"unknown", "listed", "not_listed", "no_cve_alias"}, "invalid KEV status")
        date.fromisoformat(text(record.get("next_review"), "next_review"))
        if state == "fixed":
            text(record.get("fixed_versions"), "fixed_versions")
        if state == "not_affected":
            text(record.get("justification"), "not_affected justification")
        if record["kev_status"] in {"listed", "not_listed"}:
            date.fromisoformat(text(record.get("kev_checked"), "kev_checked"))
        aliases = record.get("aliases", [])
        require(isinstance(aliases, list) and all(isinstance(a, str) for a in aliases), "invalid register aliases")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("unexpected KEV redirect; review the official feed URL")


def download_kev(output: Path) -> None:
    request = urllib.request.Request(KEV_URL, headers={"User-Agent": "dnsdaddy-assurance/1"})
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=30) as response:
        raw = response.read(MAX_BYTES + 1)
    decode(raw)  # Reject HTML error pages and oversized input before saving.
    output.write_bytes(raw)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-register")
    validate.add_argument("path", type=Path)
    download = sub.add_parser("download-kev")
    download.add_argument("output", type=Path)
    report = sub.add_parser("correlate")
    report.add_argument("--scan", type=Path, required=True)
    report.add_argument("--kev", type=Path, required=True)
    report.add_argument("--commit", required=True)
    report.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-register":
            validate_register(load(args.path)[0])
        elif args.command == "download-kev":
            download_kev(args.output)
        else:
            require(SHA.fullmatch(args.commit) is not None, "commit must be a full lowercase Git SHA")
            scan, scan_hash = load(args.scan)
            kev, kev_hash = load(args.kev)
            result = correlate(scan, kev, datetime.now(timezone.utc))
            result.update(commit=args.commit, scan_sha256=scan_hash, kev_sha256=kev_hash)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            return 1 if result["kev_match_count"] else 0
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        # Do not echo remote input, operator paths or credentials into CI logs.
        print(f"Assurance assessment unavailable ({type(exc).__name__}); inspect inputs and job logs.", file=sys.stderr)
        if args.command == "correlate":
            try:
                args.output.write_text(json.dumps({"schema_version": 1, "assessment": "unavailable"}) + "\n", encoding="utf-8")
            except OSError:
                pass
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
