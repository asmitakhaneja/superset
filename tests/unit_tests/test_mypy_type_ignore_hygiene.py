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
"""Regression guard for the mypy ``# type: ignore`` cleanup (issue #9).

The mypy config disables ``warn_unused_ignores`` for a shrinking list of
modules with dynamic type assignments.  Once a module has been paid down and
removed from that list, two properties must hold forever after:

* it must not silently creep back into the override list, and
* every remaining ``# type: ignore`` in it must be *targeted*
  (``# type: ignore[error-code]``) rather than a blanket ignore that would
  mask future, unrelated errors.

These checks would have failed before the cleanup, when the modules below were
still in the override list and carried blanket ``# type: ignore`` comments.
"""

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Modules paid down and removed from the ``warn_unused_ignores = false``
# override in pyproject.toml.  They must stay out of the override list and keep
# only targeted ignores (or, ideally, none at all).
CLEANED_MODULES = ("superset.tags.filters",)

# Matches ``# type: ignore`` that is NOT immediately followed by ``[code]``.
BLANKET_IGNORE_RE = re.compile(r"#\s*type:\s*ignore(?!\[)")


def _override_modules_without_unused_ignore_warning() -> set[str]:
    """Return modules whose mypy override disables ``warn_unused_ignores``."""
    with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
        config = tomllib.load(fh)
    modules: set[str] = set()
    for override in config["tool"]["mypy"]["overrides"]:
        if override.get("warn_unused_ignores") is False:
            module = override.get("module", [])
            if isinstance(module, str):
                module = [module]
            modules.update(module)
    return modules


def _module_to_path(module: str) -> Path:
    return REPO_ROOT / (module.replace(".", "/") + ".py")


def test_cleaned_modules_are_not_in_override_list() -> None:
    overridden = _override_modules_without_unused_ignore_warning()
    still_overridden = sorted(set(CLEANED_MODULES) & overridden)
    assert not still_overridden, (
        "These modules were paid down but reappeared in the "
        "warn_unused_ignores=false override in pyproject.toml: "
        f"{still_overridden}"
    )


@pytest.mark.parametrize("module", CLEANED_MODULES)
def test_cleaned_modules_use_only_targeted_ignores(module: str) -> None:
    path = _module_to_path(module)
    assert path.exists(), f"Expected module file to exist: {path}"
    offending = [
        f"{path.relative_to(REPO_ROOT)}:{lineno}: {line.strip()}"
        for lineno, line in enumerate(path.read_text().splitlines(), start=1)
        if BLANKET_IGNORE_RE.search(line)
    ]
    assert not offending, (
        "Blanket '# type: ignore' comments must be targeted with an error code "
        f"(e.g. '# type: ignore[union-attr]') in {module}:\n" + "\n".join(offending)
    )
