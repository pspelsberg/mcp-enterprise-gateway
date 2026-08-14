from pathlib import Path
import ast

SLICES = {"privacy": {"knowledge", "sandbox", "security_prompt"}, "knowledge": {"privacy", "sandbox", "security_prompt"}, "sandbox": {"privacy", "knowledge", "security_prompt"}, "core": {"privacy", "knowledge", "sandbox", "security_prompt"}}
def test_F_FIT_slices_do_not_import_each_other():
    for slice_name, forbidden in SLICES.items():
        for path in (Path("src") / slice_name).glob("*.py"):
            tree = ast.parse(path.read_text())
            imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
            imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
            assert not any(any(f"src.{name}" in imp for name in forbidden) for imp in imports), path
