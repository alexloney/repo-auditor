from unittest.mock import MagicMock, patch

from auditor.scanners.taint import TaintAgentScanner, TAINT_SYSTEM_PROMPT

@patch("auditor.scanners.taint.run_agent_loop")
def test_taint_scanner_runs_agent_with_repo_tools(mock_loop, tmp_path):
    scanner = TaintAgentScanner(client=MagicMock(), model="m", target_dir=tmp_path,
                                ledger_path=tmp_path / "l.json", max_turns=42)

    scanner.run()

    kwargs = mock_loop.call_args.kwargs
    assert kwargs["system_prompt"] == TAINT_SYSTEM_PROMPT
    assert kwargs["max_turns"] == 42
    assert kwargs["coverage"] is not None
    assert {t.__name__ for t in kwargs["tools"]} == {
        "list_files", "read_file", "read_file_range", "search_code", "report_issue",
    }
