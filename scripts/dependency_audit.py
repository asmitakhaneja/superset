# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Dependency-audit allowlist parser and CI gate.

This module backs the ``dep-audit`` CI workflow. It has two jobs:

1. Validate the ``.github/dep-audit-allowlist.yaml`` file against a fixed
   schema (used both by CI and by ``tests/security/test_dep_audit_allowlist.py``).
2. Consume the JSON reports produced by ``pip-audit`` and ``npm audit``, filter
   out advisories that have been explicitly triaged in the allowlist, and fail
   the build when any non-allowlisted advisory remains.

The allowlist exists because Apache Superset's threat model (see ``SECURITY.md``)
places several classes of advisory out of scope (dev-only tooling,
operator-boundary connectors, transitive dependencies) and time-boxes the
acceptance of in-scope advisories that are pending a dependency upgrade. Every
suppressed advisory must therefore be documented in a reviewable artifact rather
than living as tribal knowledge.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Fields every allowlist entry must define. Kept in sync with the schema
# documented in SECURITY.md ("Dependency-audit allowlist").
REQUIRED_FIELDS: tuple[str, ...] = (
    "id",
    "package",
    "reason",
    "security-md-scope-row",
    "owner",
    "review-by",
)

# Eligibility categories. Each maps to a row in the SECURITY.md
# "Dependency-audit allowlist" table and constrains why an advisory may be
# suppressed. Keep this in sync with that table.
VALID_SCOPE_ROWS: tuple[str, ...] = (
    "dev-tooling",
    "operator-boundary",
    "transitive-dependency",
    "tracked-upgrade",
)

VALID_ECOSYSTEMS: tuple[str, ...] = ("pip", "npm")

# npm audit severity ladder (ascending).
NPM_SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "moderate", "high", "critical")

_GHSA_RE = re.compile(
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}",
    re.IGNORECASE,
)


class AllowlistError(Exception):
    """Raised when the allowlist file cannot be parsed."""


@dataclass(frozen=True)
class AllowlistEntry:
    """A single triaged advisory suppression."""

    id: str
    package: str
    reason: str
    scope_row: str
    owner: str
    review_by: str
    ecosystem: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass(frozen=True)
class Finding:
    """A vulnerability reported by an audit tool."""

    id: str
    package: str
    ecosystem: str
    severity: str | None = None
    aliases: tuple[str, ...] = ()

    @property
    def all_ids(self) -> set[str]:
        return {self.id, *self.aliases}


def load_allowlist(path: str | Path) -> list[AllowlistEntry]:
    """Load and parse the allowlist file into typed entries.

    Raises AllowlistError on structural problems (missing file, wrong top-level
    shape). Per-entry schema violations are reported by validate_allowlist so
    that every problem can be surfaced at once.
    """
    path = Path(path)
    if not path.exists():
        raise AllowlistError(f"Allowlist file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise AllowlistError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise AllowlistError(
            f"Allowlist root must be a mapping, got {type(data).__name__}"
        )
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        raise AllowlistError("Allowlist 'entries' must be a list")

    parsed: list[AllowlistEntry] = []
    for raw in entries:
        if not isinstance(raw, dict):
            raise AllowlistError(f"Allowlist entry must be a mapping, got {raw!r}")
        parsed.append(
            AllowlistEntry(
                id=str(raw.get("id", "")),
                package=str(raw.get("package", "")),
                reason=str(raw.get("reason", "")),
                scope_row=str(raw.get("security-md-scope-row", "")),
                owner=str(raw.get("owner", "")),
                review_by=str(raw.get("review-by", "")),
                ecosystem=(str(raw["ecosystem"]) if raw.get("ecosystem") else None),
                raw=raw,
            )
        )
    return parsed


def _parse_review_by(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def _validate_entry(entry: AllowlistEntry, label: str, today: dt.date) -> list[str]:
    errors: list[str] = []
    for f in REQUIRED_FIELDS:
        value = entry.raw.get(f)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"{label}: missing required field '{f}'")

    if entry.scope_row and entry.scope_row not in VALID_SCOPE_ROWS:
        errors.append(
            f"{label}: security-md-scope-row '{entry.scope_row}' is not one of "
            f"{', '.join(VALID_SCOPE_ROWS)}"
        )
    if entry.ecosystem and entry.ecosystem not in VALID_ECOSYSTEMS:
        errors.append(
            f"{label}: ecosystem '{entry.ecosystem}' is not one of "
            f"{', '.join(VALID_ECOSYSTEMS)}"
        )
    if entry.review_by:
        review_date = _parse_review_by(entry.review_by)
        if review_date is None:
            errors.append(
                f"{label}: review-by '{entry.review_by}' is not an ISO date "
                "(YYYY-MM-DD)"
            )
        elif review_date < today:
            errors.append(
                f"{label}: review-by {entry.review_by} is stale "
                f"(before {today.isoformat()}); re-triage or bump the date"
            )
    return errors


def validate_allowlist(
    entries: list[AllowlistEntry],
    today: dt.date | None = None,
) -> list[str]:
    """Return a list of human-readable schema errors (empty when valid).

    Checks, per entry:
      * every required field is present and non-empty;
      * ``security-md-scope-row`` is one of the documented categories;
      * ``ecosystem`` (when set) is pip or npm;
      * ``review-by`` is an ISO date that has not gone stale.
    Also flags duplicate (ecosystem, id, package) triples.
    """
    today = today or dt.date.today()
    errors: list[str] = []
    seen: set[tuple[str | None, str, str]] = set()

    for index, entry in enumerate(entries):
        # Use identifying fields in the label when present so the message stays
        # useful, otherwise fall back to the positional index.
        label = (
            f"entry '{entry.id}' ({entry.package or '?'})"
            if entry.id
            else f"entry #{index + 1}"
        )
        errors.extend(_validate_entry(entry, label, today))

        key = (entry.ecosystem, entry.id, entry.package)
        if entry.id and key in seen:
            errors.append(f"{label}: duplicate allowlist entry for {key}")
        seen.add(key)

    return errors


def _entry_matches(entry: AllowlistEntry, finding: Finding) -> bool:
    if entry.ecosystem and entry.ecosystem != finding.ecosystem:
        return False
    if entry.package.lower() != finding.package.lower():
        return False
    return entry.id in finding.all_ids


def partition_findings(
    findings: list[Finding],
    entries: list[AllowlistEntry],
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (blocking, allowlisted)."""
    blocking: list[Finding] = []
    allowlisted: list[Finding] = []
    for finding in findings:
        if any(_entry_matches(entry, finding) for entry in entries):
            allowlisted.append(finding)
        else:
            blocking.append(finding)
    return blocking, allowlisted


def parse_pip_audit(report: dict[str, Any]) -> list[Finding]:
    """Extract findings from a ``pip-audit -f json`` report.

    pip-audit does not attach a severity, so every reported advisory is treated
    as blocking unless allowlisted.
    """
    findings: list[Finding] = []
    dependencies = report.get(
        "dependencies", report if isinstance(report, list) else []
    )
    for dep in dependencies:
        name = dep.get("name", "")
        for vuln in dep.get("vulns", []) or []:
            aliases = tuple(vuln.get("aliases", []) or [])
            findings.append(
                Finding(
                    id=vuln.get("id", ""),
                    package=name,
                    ecosystem="pip",
                    severity=None,
                    aliases=aliases,
                )
            )
    return findings


def _severity_at_least(severity: str | None, threshold: str) -> bool:
    if severity is None:
        return True
    try:
        return NPM_SEVERITY_ORDER.index(severity) >= NPM_SEVERITY_ORDER.index(threshold)
    except ValueError:
        # Unknown severity string: fail closed.
        return True


def parse_npm_audit(
    report: dict[str, Any], fail_severity: str = "critical"
) -> list[Finding]:
    """Extract findings from an ``npm audit --json`` report (npm >= 7).

    Only advisories at or above ``fail_severity`` are returned. Each concrete
    advisory (a dict entry in a package's ``via`` list) becomes one finding,
    keyed by its GHSA id so it can be matched against the allowlist.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    vulnerabilities = report.get("vulnerabilities", {}) or {}
    for pkg in vulnerabilities.values():
        for via in pkg.get("via", []) or []:
            if not isinstance(via, dict):
                # A string via points at another vulnerable package that has its
                # own top-level entry; skip to avoid double counting.
                continue
            severity = via.get("severity")
            if not _severity_at_least(severity, fail_severity):
                continue
            advisory_id = _ghsa_from(via)
            package = via.get("name", "")
            key = (advisory_id, package)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=advisory_id,
                    package=package,
                    ecosystem="npm",
                    severity=severity,
                )
            )
    return findings


def _ghsa_from(via: dict[str, Any]) -> str:
    for value in (via.get("url", ""), via.get("title", ""), str(via.get("source", ""))):
        match = _GHSA_RE.search(value)
        if match:
            return match.group(0)
    # Fall back to the numeric advisory source id.
    return str(via.get("source", "")) or via.get("url", "")


def _load_json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def _cmd_validate(args: argparse.Namespace) -> int:
    entries = load_allowlist(args.allowlist)
    if errors := validate_allowlist(entries):
        print(f"Allowlist {args.allowlist} is INVALID:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(f"Allowlist {args.allowlist} is valid ({len(entries)} entries).")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    entries = load_allowlist(args.allowlist)
    if schema_errors := validate_allowlist(entries):
        print("Refusing to run gate: allowlist is invalid:")
        for error in schema_errors:
            print(f"  - {error}")
        return 1

    findings: list[Finding] = []
    for pip_report in args.pip_audit_json or []:
        findings.extend(parse_pip_audit(_load_json(pip_report)))
    for npm_report in args.npm_audit_json or []:
        findings.extend(
            parse_npm_audit(
                _load_json(npm_report), fail_severity=args.npm_fail_severity
            )
        )

    blocking, allowlisted = partition_findings(findings, entries)

    if allowlisted:
        print(f"Allowlisted advisories ({len(allowlisted)}):")
        for finding in sorted(
            allowlisted, key=lambda f: (f.ecosystem, f.package, f.id)
        ):
            print(f"  - [{finding.ecosystem}] {finding.package}: {finding.id}")

    if blocking:
        print()
        print(f"::error::{len(blocking)} non-allowlisted advisory(ies) found:")
        for finding in sorted(blocking, key=lambda f: (f.ecosystem, f.package, f.id)):
            sev = f" ({finding.severity})" if finding.severity else ""
            print(f"  - [{finding.ecosystem}] {finding.package}: {finding.id}{sev}")
        print()
        print(
            "Triage each advisory per SECURITY.md and, if out of scope or pending an "
            "upgrade, add an entry to the dependency-audit allowlist."
        )
        return 1

    print("No non-allowlisted advisories found.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allowlist",
        default=str(
            Path(__file__).resolve().parents[1] / ".github" / "dep-audit-allowlist.yaml"
        ),
        help="Path to the dependency-audit allowlist YAML.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="Validate the allowlist schema.")
    validate.set_defaults(func=_cmd_validate)

    check = sub.add_parser("check", help="Fail on non-allowlisted advisories.")
    check.add_argument(
        "--pip-audit-json",
        action="append",
        default=[],
        help="Path to a pip-audit JSON report (repeatable).",
    )
    check.add_argument(
        "--npm-audit-json",
        action="append",
        default=[],
        help="Path to an npm audit JSON report (repeatable).",
    )
    check.add_argument(
        "--npm-fail-severity",
        default="critical",
        choices=NPM_SEVERITY_ORDER,
        help="Minimum npm severity that fails the gate (default: critical).",
    )
    check.set_defaults(func=_cmd_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
