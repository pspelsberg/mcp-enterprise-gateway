"""F-FIT import-boundary ratchets for the modular-monolith slices."""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path("src")
SLICES = {"privacy", "knowledge", "sandbox", "security_prompt"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    values: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            values.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level >= 2:
                values.add("__cross_package_relative_import__")
            elif node.module:
                values.add(node.module)
    return values


def test_F_FIT_feature_slices_only_depend_on_core_or_themselves():
    for slice_name in SLICES:
        for path in (ROOT / slice_name).rglob("*.py"):
            imports = _imports(path)
            forbidden = {f"src.{other}" for other in SLICES - {slice_name}}
            assert not any(imported == "__cross_package_relative_import__" or any(
                imported == prefix or imported.startswith(prefix + ".") for prefix in forbidden
            ) for imported in imports), path


def test_F_FIT_only_composition_root_may_depend_on_multiple_feature_slices():
    for path in ROOT.rglob("*.py"):
        if path == ROOT / "server.py":
            continue
        imports = _imports(path)
        dependencies = {
            slice_name for slice_name in SLICES
            if any(imported == f"src.{slice_name}" or imported.startswith(f"src.{slice_name}.") for imported in imports)
        }
        assert len(dependencies) <= 1, path
