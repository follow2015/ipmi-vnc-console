"""scan-secrets: fixtures-allowed — 本文件刻意构造明文凭据样本验证闸门拦截逻辑，这些字面量是测试输入而非真实机密。"""
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
    assert gate.check_document_plaintext_secrets(ROOT) == []


def test_gate_allows_only_the_value_free_env_template(monkeypatch):
    import subprocess
    from types import SimpleNamespace

    names = [".env.example", ".env.local", "deploy/.env", "keys/id_rsa", "README.md"]

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(
            args, 0, stdout="\0".join(names) + "\0", stderr="")

    monkeypatch.setattr(gate, "subprocess", SimpleNamespace(run=fake_run))
    assert gate.tracked_secrets(ROOT) == [".env.local", "deploy/.env", "keys/id_rsa"]


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


def test_gate_catches_plaintext_credential_in_doc_prose(tmp_path):
    import subprocess
    (tmp_path / "docs").mkdir()
    note = tmp_path / "docs" / "note.md"
    note.write_text('# 排障记录\n\nBMC 登录用 "root:calvin" 可成功。\n')
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=False)
    subprocess.run(["git", "add", "docs/note.md"], cwd=tmp_path, check=False)
    findings = gate.check_document_plaintext_secrets(tmp_path)
    assert findings, "a plaintext credential in docs must fail the gate"
    assert any("CREDENTIAL_PAIR" in f and "note.md" in f for f in findings)


def test_gate_ignores_narrative_password_word_in_docs(tmp_path):
    import subprocess
    (tmp_path / "docs").mkdir()
    note = tmp_path / "docs" / "note.md"
    note.write_text('看到 Password: 提示符后输入，VNC 密码 write-only。\n')
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=False)
    subprocess.run(["git", "add", "docs/note.md"], cwd=tmp_path, check=False)
    assert gate.check_document_plaintext_secrets(tmp_path) == []


def test_gate_detects_unpinned_or_drifted_lockfile(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies=["demo==1.2.3"]\n')
    (tmp_path / "requirements.lock").write_text("demo==1.2.3\n")
    assert gate.check_lockfile(tmp_path) == []
    (tmp_path / "requirements.lock").write_text("demo>=1.2.3\n")
    assert any("unpinned" in problem for problem in gate.check_lockfile(tmp_path))
    (tmp_path / "requirements.lock").write_text("demo==9.9.9\n")
    assert any("mismatch" in problem for problem in gate.check_lockfile(tmp_path))
