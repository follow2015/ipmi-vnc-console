"""I-4: the local/CI gate must fail loudly on security regressions."""
from pathlib import Path

from tools import gate

ROOT = Path(__file__).resolve().parents[1]


def test_gate_detects_missing_ignore_rules(tmp_path):
    (tmp_path / ".gitignore").write_text(".venv/\n")
    missing = gate.check_gitignore(tmp_path)
    assert ".DS_Store" in missing
    assert "*.key" in missing


def test_repository_gate_is_clean():
    assert gate.check_gitignore(ROOT) == []
    assert gate.tracked_secrets(ROOT) == []
    assert gate.check_error_codes() == []
    assert gate.check_lockfile(ROOT) == []


def test_gate_detects_unpinned_or_drifted_lockfile(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["demo==1.2.3"]\n')
    (tmp_path / "requirements.lock").write_text("demo==1.2.3\n")
    assert gate.check_lockfile(tmp_path) == []
    (tmp_path / "requirements.lock").write_text("demo>=1.2.3\n")
    assert any("unpinned" in problem for problem in gate.check_lockfile(tmp_path))
    (tmp_path / "requirements.lock").write_text("demo==9.9.9\n")
    assert any("mismatch" in problem for problem in gate.check_lockfile(tmp_path))
