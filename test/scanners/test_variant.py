import subprocess
from unittest.mock import MagicMock, patch

import pytest

from auditor.scanners.variant import VariantAgentScanner, VARIANT_SYSTEM_PROMPT

def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

def commit_all(repo, *messages):
    git(repo, "add", ".")
    args = []
    for m in messages:
        args += ["-m", m]
    git(repo, "commit", "-q", *args)

@pytest.fixture
def repo(tmp_path):
    """A small history: a feature, an unrelated fix, and a path traversal fix with a CVE."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "commit.gpgsign", "false")

    (repo / "files.py").write_text("def download(name):\n    return open('/data/' + name).read()\n", encoding="utf-8")
    (repo / "export.py").write_text("def export(name):\n    return open('/data/' + name).read()\n", encoding="utf-8")
    commit_all(repo, "Add download endpoint")

    (repo / "CHANGELOG.md").write_text("typo fix\n", encoding="utf-8")
    commit_all(repo, "Fix typo in changelog")

    (repo / "files.py").write_text(
        "import os\n\ndef download(name):\n    if '..' in name:\n        raise ValueError\n"
        "    return open('/data/' + name).read()\n", encoding="utf-8")
    (repo / "CHANGELOG.md").write_text("Fixed path traversal\n", encoding="utf-8")
    commit_all(repo, "Fix path traversal in download", "Fixes CVE-2024-12345.")
    return repo

def make_scanner(target, **kwargs):
    return VariantAgentScanner(client=MagicMock(), model="m", target_dir=target,
                               ledger_path=target.parent / "l.json", extensions=[".py"], **kwargs)

TRIAGE_YES = {
    "is_security_fix": True, "vuln_class": "CWE-22", "summary": "s",
    "vulnerable_pattern": "open('/data/' + name)", "fix_mechanism": "reject '..'",
    "search_terms": ["open('/data/'"],
}

def test_candidate_commits_finds_security_fixes_only(repo):
    commits = make_scanner(repo)._candidate_commits()

    assert [c.subject for c in commits] == ["Fix path traversal in download"]
    assert commits[0].references == ["CVE-2024-12345"]

def test_candidate_commits_put_advisory_tagged_first(repo):
    (repo / "export.py").write_text("def export(name):\n    return name\n", encoding="utf-8")
    commit_all(repo, "Harden export against injection")

    commits = make_scanner(repo)._candidate_commits()

    assert [c.subject for c in commits] == ["Fix path traversal in download", "Harden export against injection"]

def test_commit_diff_keeps_only_auditable_files(repo):
    scanner = make_scanner(repo)
    sha = scanner._candidate_commits()[0].sha

    diff = scanner._commit_diff(sha)

    assert "files.py" in diff
    assert "CHANGELOG.md" not in diff

def test_trim_diff_truncates_large_diffs(repo, monkeypatch):
    monkeypatch.setattr("auditor.scanners.variant.MAX_DIFF_TOKENS", 10)
    diff = "diff --git a/x.py b/x.py\n" + "+line\n" * 500

    trimmed = make_scanner(repo)._trim_diff(diff)

    assert trimmed.endswith("[... diff truncated ...]\n")
    assert len(trimmed) < len(diff)

def test_not_a_git_repo_warns_and_skips(tmp_path):
    target = tmp_path / "plain"
    target.mkdir()
    warnings = []
    scanner = make_scanner(target, on_warning=warnings.append)

    with patch("auditor.scanners.variant.run_agent_loop") as mock_loop:
        scanner.run()

    assert mock_loop.call_count == 0
    assert any("cannot read git history" in w for w in warnings)

@patch("auditor.scanners.variant.run_agent_loop")
@patch("auditor.scanners.variant.call_json")
def test_run_skips_commits_triage_rejects(mock_call, mock_loop, repo):
    mock_call.return_value = {**TRIAGE_YES, "is_security_fix": False}

    make_scanner(repo).run()

    assert mock_call.call_count == 1
    assert mock_loop.call_count == 0

@patch("auditor.scanners.variant.run_agent_loop")
@patch("auditor.scanners.variant.call_json", return_value=TRIAGE_YES)
def test_run_hunts_each_confirmed_seed(mock_call, mock_loop, repo):
    make_scanner(repo, max_turns=100, options={"variant_turns_per_seed": 12}).run()

    kwargs = mock_loop.call_args.kwargs
    assert kwargs["system_prompt"] == VARIANT_SYSTEM_PROMPT
    assert kwargs["max_turns"] == 12
    assert "CVE-2024-12345" in kwargs["initial_user_prompt"]
    assert "files.py" in kwargs["initial_user_prompt"]
    assert {t.__name__ for t in kwargs["tools"]} == {
        "list_files", "read_file", "read_file_range", "search_code", "report_issue",
    }

@patch("auditor.scanners.variant.run_agent_loop")
@patch("auditor.scanners.variant.call_json", return_value=TRIAGE_YES)
def test_turns_per_seed_capped_by_max_turns(mock_call, mock_loop, repo):
    make_scanner(repo, max_turns=5, options={"variant_turns_per_seed": 50}).run()

    assert mock_loop.call_args.kwargs["max_turns"] == 5

@patch("auditor.scanners.variant.run_agent_loop")
@patch("auditor.scanners.variant.call_json", return_value=TRIAGE_YES)
def test_max_seeds_limits_hunts(mock_call, mock_loop, repo):
    for i in range(3):
        (repo / f"m{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
        commit_all(repo, f"Fix XSS {i}")

    make_scanner(repo, options={"variant_max_seeds": 2}).run()

    assert mock_loop.call_count == 2

@patch("auditor.scanners.variant.run_agent_loop")
@patch("auditor.scanners.variant.call_json", return_value=TRIAGE_YES)
def test_findings_are_stamped_with_seed(mock_call, mock_loop, repo):
    scanner = make_scanner(repo)
    recorded = []
    scanner.record_finding = recorded.append

    scanner.run()
    report_issue = next(t for t in mock_loop.call_args.kwargs["tools"] if t.__name__ == "report_issue")
    result = report_issue(filepath="export.py", line=2, title="Unpatched sibling", description="d",
                          evidence="return open('/data/' + name).read()", category="bug")

    assert result == "Issue successfully logged to the ledger."
    finding = recorded[0]
    assert finding["category"] == "security"
    assert finding["vuln_class"] == "CWE-22"  # inherited from triage when the agent omits it
    assert finding["seed_subject"] == "Fix path traversal in download"
    assert finding["seed_references"] == ["CVE-2024-12345"]
    assert len(finding["seed_commit"]) == 40
