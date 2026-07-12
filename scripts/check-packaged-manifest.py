#!/usr/bin/env python3
"""Reject non-registry dependencies in Cargo-normalized package manifests."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import Any


DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
FORBIDDEN_DEPENDENCY_KEYS = ("path", "git", "workspace")


def fail(path: Path, message: str) -> None:
    print(f"packaged manifest audit failed ({path}): {message}", file=sys.stderr)
    raise SystemExit(1)


def audit_dependency_table(path: Path, scope: str, table: Any) -> None:
    if table is None:
        return
    if not isinstance(table, dict):
        fail(path, f"{scope} is not a table")

    for name, specification in table.items():
        if isinstance(specification, str):
            continue
        if not isinstance(specification, dict):
            fail(path, f"{scope}.{name} has an invalid specification")
        leaked = [key for key in FORBIDDEN_DEPENDENCY_KEYS if key in specification]
        if leaked:
            fail(path, f"{scope}.{name} leaks {', '.join(leaked)}")
        if "version" not in specification:
            fail(path, f"{scope}.{name} has no registry version")


def audit_manifest(path: Path) -> None:
    with path.open("rb") as manifest_file:
        manifest = tomllib.load(manifest_file)

    for forbidden in ("patch", "replace", "workspace"):
        if forbidden in manifest:
            fail(path, f"Cargo-normalized archive contains [{forbidden}]")

    for table_name in DEPENDENCY_TABLES:
        audit_dependency_table(path, table_name, manifest.get(table_name))

    targets = manifest.get("target", {})
    if not isinstance(targets, dict):
        fail(path, "target is not a table")
    for target_name, target in targets.items():
        if not isinstance(target, dict):
            fail(path, f"target.{target_name} is not a table")
        for table_name in DEPENDENCY_TABLES:
            audit_dependency_table(
                path,
                f"target.{target_name}.{table_name}",
                target.get(table_name),
            )

    print(f"packaged-manifest: PASS ({path.parent.name})")


if len(sys.argv) < 2:
    print(f"usage: {Path(sys.argv[0]).name} MANIFEST...", file=sys.stderr)
    raise SystemExit(2)

for argument in sys.argv[1:]:
    manifest_path = Path(argument)
    if not manifest_path.is_file():
        fail(manifest_path, "manifest does not exist")
    audit_manifest(manifest_path)
