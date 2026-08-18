#!/usr/bin/env python3
"""Bump the package version, commit, and tag — the release trigger.

    python scripts/bump.py 0.1.1

Updates the version in pyproject.toml and src/lookalike_radar/__init__.py, makes
a release commit, and creates an annotated tag ``v<version>``. Pushing that tag
(``git push origin main --tags``) fires .github/workflows/release.yml, which
publishes to PyPI via Trusted Publishing (OIDC — no token).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "lookalike_radar" / "__init__.py"

_SEMVER = re.compile(r"^\d+\.\d+\.\d+([abrc.\d]*)?$")


def _replace(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, replacement, text, count=1, flags=re.M)
    if n != 1:
        sys.exit(f"error: could not update version in {path}")
    path.write_text(new, encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2 or not _SEMVER.match(sys.argv[1]):
        sys.exit("usage: python scripts/bump.py <version>  (e.g. 0.1.1)")
    version = sys.argv[1]

    _replace(PYPROJECT, r'^version = ".*"', f'version = "{version}"')
    _replace(INIT, r'^__version__ = ".*"', f'__version__ = "{version}"')

    subprocess.run(["git", "add", str(PYPROJECT), str(INIT)], cwd=ROOT, check=True)
    subprocess.run(["git", "commit", "-m", f"release {version}"], cwd=ROOT, check=True)
    subprocess.run(["git", "tag", "-a", f"v{version}", "-m", f"v{version}"],
                   cwd=ROOT, check=True)
    print(f"tagged v{version} — push with:  git push origin main --tags")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
