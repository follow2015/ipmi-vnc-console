"""C-2 regression: generated run directories must never leak keys into git."""
import subprocess
from pathlib import Path

from tools.bootstrap import generate

ROOT = Path(__file__).resolve().parents[1]


def test_repository_ignore_rules_cover_secrets_and_macos_cruft():
    rules = [line.strip() for line in (ROOT / ".gitignore").read_text().splitlines()]
    for required in (".venv/", ".local*/", ".DS_Store", ".env", ".env.*", "*.pem", "*.key"):
        assert required in rules, f"missing ignore rule: {required}"


def test_local_log_file_is_ignored_not_only_local_directories():
    result = subprocess.run(
        ["git", "check-ignore", "-q", ".local-public-check.log"],
        cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, "`.local*/` only ignores directories"


def test_bootstrap_writes_directory_level_gitignore(tmp_path):
    root = generate(tmp_path / "arbitrary-run")
    guard = [line.strip() for line in (root / ".gitignore").read_text().splitlines()]
    assert "*" in guard
    assert "!.gitignore" in guard
    assert (root / "signing.key").exists()
    assert (root / "encryption.key").exists()
