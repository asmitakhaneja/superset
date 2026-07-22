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
"""Tests for the dependency-audit allowlist and CI gate.

These guard the invariants the `dep-audit` workflow relies on: the checked-in
allowlist is schema-valid and non-stale, and the gate blocks any advisory that
is not explicitly allowlisted.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from scripts.dependency_audit import (
    AllowlistError,
    Finding,
    load_allowlist,
    parse_npm_audit,
    parse_pip_audit,
    partition_findings,
    REQUIRED_FIELDS,
    VALID_SCOPE_ROWS,
    validate_allowlist,
)

ALLOWLIST_PATH = (
    Path(__file__).resolve().parents[2] / ".github" / "dep-audit-allowlist.yaml"
)


def _write_allowlist(tmp_path: Path, entries_yaml: str) -> Path:
    path = tmp_path / "allowlist.yaml"
    path.write_text("version: 1\nentries:\n" + entries_yaml)
    return path


def _valid_entry(**overrides: str) -> str:
    fields = {
        "id": "CVE-2099-0001",
        "package": "somepkg",
        "ecosystem": "pip",
        "reason": "example",
        "security-md-scope-row": "dev-tooling",
        "owner": "@apache/superset-committers",
        "review-by": "2099-01-01",
    }
    fields.update(overrides)
    return "  - " + "\n    ".join(f'{k}: "{v}"' for k, v in fields.items()) + "\n"


# --- the checked-in allowlist ------------------------------------------------


def test_checked_in_allowlist_is_schema_valid_and_fresh() -> None:
    entries = load_allowlist(ALLOWLIST_PATH)
    assert entries, "the committed allowlist should not be empty"
    errors = validate_allowlist(entries)
    assert errors == [], "committed allowlist is invalid:\n" + "\n".join(errors)


def test_every_committed_entry_has_all_required_fields() -> None:
    entries = load_allowlist(ALLOWLIST_PATH)
    for entry in entries:
        for required in REQUIRED_FIELDS:
            value = entry.raw.get(required)
            assert value not in (None, ""), (
                f"entry {entry.id!r} is missing required field {required!r}"
            )
        assert entry.scope_row in VALID_SCOPE_ROWS
        # review-by must be a real, non-stale ISO date.
        review = dt.date.fromisoformat(entry.review_by)
        assert review >= dt.date.today(), (
            f"entry {entry.id!r} has a stale review-by ({entry.review_by})"
        )


# --- schema validation -------------------------------------------------------


def test_missing_required_field_is_reported(tmp_path: Path) -> None:
    path = _write_allowlist(
        tmp_path,
        _valid_entry() + '  - id: "CVE-2099-0002"\n    package: "other"\n',
    )
    errors = validate_allowlist(load_allowlist(path))
    assert any("missing required field" in error for error in errors)


def test_invalid_scope_row_is_reported(tmp_path: Path) -> None:
    path = _write_allowlist(
        tmp_path, _valid_entry(**{"security-md-scope-row": "made-up"})
    )
    errors = validate_allowlist(load_allowlist(path))
    assert any("security-md-scope-row" in error for error in errors)


def test_stale_review_by_is_reported(tmp_path: Path) -> None:
    path = _write_allowlist(tmp_path, _valid_entry(**{"review-by": "2000-01-01"}))
    errors = validate_allowlist(load_allowlist(path))
    assert any("stale" in error for error in errors)


def test_non_iso_review_by_is_reported(tmp_path: Path) -> None:
    path = _write_allowlist(tmp_path, _valid_entry(**{"review-by": "next-quarter"}))
    errors = validate_allowlist(load_allowlist(path))
    assert any("ISO date" in error for error in errors)


def test_duplicate_entry_is_reported(tmp_path: Path) -> None:
    path = _write_allowlist(tmp_path, _valid_entry() + _valid_entry())
    errors = validate_allowlist(load_allowlist(path))
    assert any("duplicate" in error for error in errors)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(AllowlistError):
        load_allowlist(tmp_path / "nope.yaml")


# --- gate behaviour ----------------------------------------------------------


def test_allowlisted_finding_does_not_block() -> None:
    entries = load_allowlist(ALLOWLIST_PATH)
    finding = Finding(
        id="GHSA-55h3-fm53-wq99",
        package="eslint-plugin-i18n-strings",
        ecosystem="npm",
        severity="critical",
    )
    blocking, allowlisted = partition_findings([finding], entries)
    assert blocking == []
    assert allowlisted == [finding]


def test_new_advisory_blocks_the_gate() -> None:
    """A newly introduced advisory that is not allowlisted must fail."""
    entries = load_allowlist(ALLOWLIST_PATH)
    finding = Finding(id="CVE-2099-9999", package="brand-new-vuln", ecosystem="pip")
    blocking, _ = partition_findings([finding], entries)
    assert blocking == [finding]


def test_removing_entry_resurfaces_advisory() -> None:
    """Dropping the allowlist entry turns a suppressed advisory back into a block."""
    entries = load_allowlist(ALLOWLIST_PATH)
    finding = Finding(
        id="GHSA-23hp-3jrh-7fpw", package="tar", ecosystem="npm", severity="critical"
    )
    assert partition_findings([finding], entries)[0] == []

    without_tar = [entry for entry in entries if entry.id != "GHSA-23hp-3jrh-7fpw"]
    assert partition_findings([finding], without_tar)[0] == [finding]


def test_matching_is_ecosystem_scoped() -> None:
    """A pip allowlist entry must not suppress a same-named npm finding."""
    entries = load_allowlist(ALLOWLIST_PATH)
    npm_lookalike = Finding(id="PYSEC-2026-2151", package="flask", ecosystem="npm")
    assert partition_findings([npm_lookalike], entries)[0] == [npm_lookalike]


def test_matching_uses_aliases() -> None:
    entries = load_allowlist(ALLOWLIST_PATH)
    pip_entry = next(entry for entry in entries if entry.ecosystem == "pip")
    # pip-audit may report a different primary id but list ours as an alias.
    finding = Finding(
        id="OTHER-ID",
        package=pip_entry.package,
        ecosystem="pip",
        aliases=(pip_entry.id,),
    )
    assert partition_findings([finding], entries)[0] == []


# --- report parsing ----------------------------------------------------------


def test_parse_pip_audit_extracts_findings() -> None:
    report = {
        "dependencies": [
            {
                "name": "pillow",
                "version": "1.0",
                "vulns": [{"id": "CVE-1", "aliases": ["GHSA-x"]}],
            },
            {"name": "clean", "version": "2.0", "vulns": []},
        ]
    }
    findings = parse_pip_audit(report)
    assert len(findings) == 1
    assert findings[0].package == "pillow"
    assert findings[0].ecosystem == "pip"
    assert "GHSA-x" in findings[0].all_ids


def test_parse_npm_audit_respects_severity_threshold() -> None:
    report = {
        "vulnerabilities": {
            "tar": {
                "severity": "critical",
                "via": [
                    {
                        "source": 1,
                        "name": "tar",
                        "url": "https://github.com/advisories/GHSA-23hp-3jrh-7fpw",
                        "severity": "critical",
                    },
                    {
                        "source": 2,
                        "name": "tar",
                        "url": "https://github.com/advisories/GHSA-8x88-c5mf-7j5w",
                        "severity": "high",
                    },
                ],
            },
        }
    }
    critical_only = parse_npm_audit(report, fail_severity="critical")
    assert {f.id for f in critical_only} == {"GHSA-23hp-3jrh-7fpw"}

    high_and_up = parse_npm_audit(report, fail_severity="high")
    assert {f.id for f in high_and_up} == {"GHSA-23hp-3jrh-7fpw", "GHSA-8x88-c5mf-7j5w"}


def test_parse_npm_audit_skips_string_via() -> None:
    report = {"vulnerabilities": {"lerna": {"severity": "moderate", "via": ["tar"]}}}
    assert parse_npm_audit(report, fail_severity="low") == []
