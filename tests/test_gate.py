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
    assert gate.check_test_imports(ROOT) == []
    assert gate.check_collection(ROOT) == []


def test_gate_catches_tests_pytest_cannot_collect(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_broken.py").write_text(
        "import tools.never_shipped\n\n\ndef test_it():\n    pass\n")
    problems = gate.check_collection(tmp_path)
    assert problems, "a test file pytest cannot import must fail the gate"
    assert "collect" in problems[0]


def test_gate_collection_rule_passes_on_a_clean_tree(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_fine.py").write_text("def test_it():\n    assert True\n")
    assert gate.check_collection(tmp_path) == []


def test_gate_catches_a_test_importing_an_absent_local_module(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "present.py").write_text("VALUE = 1\n")
    (tmp_path / "tests" / "test_ok.py").write_text(
        "from tools.present import VALUE\nimport kvmhub.common\n")
    (tmp_path / "kvmhub").mkdir()
    (tmp_path / "kvmhub" / "common.py").write_text("PORT = 1\n")
    assert gate.check_test_imports(tmp_path) == []

    (tmp_path / "tests" / "test_broken.py").write_text(
        "from tools.absent_check import Relay\n")
    problems = gate.check_test_imports(tmp_path)
    assert any("tools.absent_check" in problem for problem in problems)


def test_gate_detects_unpinned_or_drifted_lockfile(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["demo==1.2.3"]\n')
    (tmp_path / "requirements.lock").write_text("demo==1.2.3\n")
    assert gate.check_lockfile(tmp_path) == []
    (tmp_path / "requirements.lock").write_text("demo>=1.2.3\n")
    assert any("unpinned" in problem for problem in gate.check_lockfile(tmp_path))
    (tmp_path / "requirements.lock").write_text("demo==9.9.9\n")
    assert any("mismatch" in problem for problem in gate.check_lockfile(tmp_path))
