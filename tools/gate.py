"""Local / CI gate: fail loudly on security and error-code regressions."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REQUIRED_IGNORE_RULES = (".venv/", ".local*/", ".DS_Store", ".env", ".env.*", "*.pem", "*.key")
SECRET_NAME = re.compile(r"(^|/)\.env(\.|$)|\.pem$|\.key$|id_(rsa|ed25519)$")


def check_gitignore(root: Path) -> list[str]:
    path = Path(root) / ".gitignore"
    if not path.exists():
        return list(REQUIRED_IGNORE_RULES)
    rules = [line.strip() for line in path.read_text().splitlines()]
    return [rule for rule in REQUIRED_IGNORE_RULES if rule not in rules]


def tracked_secrets(root: Path) -> list[str]:
    result = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return []
    return [name for name in result.stdout.split("\0") if name and SECRET_NAME.search(name)]


def check_error_codes() -> list[str]:
    from kvmhub.common import ERROR_STATUS, Problem
    return [code for code, status in ERROR_STATUS.items()
            if not isinstance(status, int) or not 100 <= status <= 599
            or Problem(code).status != status]


def check_lockfile(root: Path) -> list[str]:
    root = Path(root)
    lock, project = root / "requirements.lock", root / "pyproject.toml"
    if not lock.exists() or not project.exists():
        return ["requirements.lock or pyproject.toml missing"]
    problems: list[str] = []
    pinned: dict[str, str] = {}
    for raw in lock.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            problems.append(f"unpinned: {line}")
            continue
        name, version = line.split("==", 1)
        pinned[name.lower().replace("_", "-")] = version
    import tomllib
    data = tomllib.loads(project.read_text())
    deps = list(data.get("project", {}).get("dependencies", []))
    for extra in data.get("project", {}).get("optional-dependencies", {}).values():
        deps.extend(extra)
    for dep in deps:
        if "==" not in dep:
            problems.append(f"pyproject unpinned: {dep}")
            continue
        name, version = dep.split("==", 1)
        key = name.lower().replace("_", "-")
        if pinned.get(key) != version:
            problems.append(f"mismatch: {dep} (lock={pinned.get(key)})")
    return problems


LOCAL_PACKAGES = ("kvmhub", "tools", "demos")


def check_test_imports(root: Path) -> list[str]:
    import ast

    root = Path(root)
    problems: list[str] = []
    for path in sorted((root / "tests").rglob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            problems.append(f"{path.relative_to(root)}: unreadable ({exc})")
            continue
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
            elif isinstance(node, ast.Import):
                modules.update(alias.name for alias in node.names)
        for module in sorted(modules):
            if module.split(".")[0] not in LOCAL_PACKAGES:
                continue
            target = root.joinpath(*module.split("."))
            if target.with_suffix(".py").is_file() or target.is_dir():
                continue
            problems.append(f"{path.relative_to(root)}: imports missing module {module}")
    return problems


COLLECT_TIMEOUT = 180


def check_collection(root: Path) -> list[str]:
    root = Path(root)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q",
             "-p", "no:cacheprovider", str(root / "tests")],
            cwd=str(root), capture_output=True, text=True,
            timeout=COLLECT_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"pytest --collect-only could not run: {exc}"]
    if result.returncode == 0:
        return []
    output = (result.stdout + result.stderr).strip().splitlines()
    tail = [line.strip() for line in output if line.strip()][-5:]
    return ["pytest --collect-only failed: " + " | ".join(tail)]


def main() -> int:
    problems = {
        "missing .gitignore rules": check_gitignore(ROOT),
        "tracked secret-like files": tracked_secrets(ROOT),
        "unstable error codes": check_error_codes(),
        "lockfile pin drift": check_lockfile(ROOT),
        "tests importing absent modules": check_test_imports(ROOT),
        "tests that pytest cannot collect": check_collection(ROOT),
    }
    failed = False
    for label, items in problems.items():
        if items:
            failed = True
            print(f"GATE FAIL: {label}: {items}", file=sys.stderr)
    if not failed:
        print("GATE OK: ignore rules, tracked secrets, error codes, lockfile pins, "
              "test imports and test collection are clean")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
