from unittest.mock import MagicMock, patch

from auditor.scanners.authorization import AuthorizationAgentScanner, AUTHZ_SYSTEM_PROMPT

@patch("auditor.scanners.authorization.run_agent_loop")
def test_authz_scanner_runs_agent_with_repo_tools(mock_loop, tmp_path):
    scanner = AuthorizationAgentScanner(client=MagicMock(), model="m", target_dir=tmp_path,
                                        ledger_path=tmp_path / "l.json", max_turns=42)

    scanner.run()

    kwargs = mock_loop.call_args.kwargs
    assert kwargs["system_prompt"] == AUTHZ_SYSTEM_PROMPT
    assert kwargs["max_turns"] == 42
    assert kwargs["coverage"] is not None
    assert {t.__name__ for t in kwargs["tools"]} == {
        "list_files", "read_file", "read_file_range", "search_code", "report_issue",
    }

@patch("auditor.scanners.authorization.run_agent_loop")
def test_authz_findings_are_forced_to_security(mock_loop, tmp_path):
    (tmp_path / "routes.py").write_text("def delete_order(order_id):\n    Order.delete(order_id)\n", encoding="utf-8")
    scanner = AuthorizationAgentScanner(client=MagicMock(), model="m", target_dir=tmp_path,
                                        ledger_path=tmp_path / "l.json")
    recorded = []
    scanner.record_finding = recorded.append

    scanner.run()
    report_issue = next(t for t in mock_loop.call_args.kwargs["tools"] if t.__name__ == "report_issue")
    report_issue(filepath="routes.py", line=2, title="IDOR", description="d",
                 evidence="Order.delete(order_id)", category="bug", vuln_class="CWE-639")

    assert recorded[0]["category"] == "security"
    assert recorded[0]["vuln_class"] == "CWE-639"
