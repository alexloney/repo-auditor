from unittest.mock import MagicMock, patch

from auditor.scanners.memory import MemorySafetyScanner, MEMORY_FINDINGS_SCHEMA, MAX_UNITS_PER_REQUEST

def make_scanner(tmp_path, extensions=None):
    scanner = MemorySafetyScanner(client=MagicMock(), model="m", target_dir=tmp_path,
                                  ledger_path=tmp_path / "ledger.json", extensions=extensions)
    scanner.on_progress, scanner.on_warning, scanner.on_error = MagicMock(), MagicMock(), MagicMock()
    return scanner

@patch("auditor.scanners.memory.append_finding")
@patch("auditor.scanners.memory.call_json")
def test_memory_scanner_reviews_c_functions_with_absolute_lines(mock_call_json, mock_append, tmp_path):
    (tmp_path / "buf.c").write_text("#define N 4\n\nvoid f(char *s) {\n    char b[N];\n    strcpy(b, s);\n}\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('ignored')\n", encoding="utf-8")
    mock_call_json.return_value = {"findings": [{"title": "Overflow", "line": 5, "file": "whatever"}]}

    make_scanner(tmp_path).run()

    mock_call_json.assert_called_once()
    _, _, _, user, schema = mock_call_json.call_args[0]
    assert schema is MEMORY_FINDINGS_SCHEMA
    assert "#define N 4" in user              # preamble supplies buffer sizes
    assert "   5 |     strcpy(b, s);" in user  # absolute line numbers in the gutter
    finding = mock_append.call_args[0][1]
    assert finding["file"] == "buf.c"
    assert finding["category"] == "security"

@patch("auditor.scanners.memory.call_json")
def test_memory_scanner_respects_extension_filter(mock_call_json, tmp_path):
    (tmp_path / "buf.c").write_text("void f(void) { }\n", encoding="utf-8")

    make_scanner(tmp_path, extensions=[".py"]).run()

    mock_call_json.assert_not_called()

@patch("auditor.scanners.memory.call_json", return_value={"findings": []})
def test_memory_scanner_chunks_by_function_count(mock_call_json, tmp_path):
    funcs = "".join(f"void f{i}(void) {{ }}\n" for i in range(MAX_UNITS_PER_REQUEST + 1))
    (tmp_path / "many.c").write_text(funcs, encoding="utf-8")

    make_scanner(tmp_path).run()

    assert mock_call_json.call_count == 2

def test_memory_schema_has_vuln_class_and_no_category():
    item = MEMORY_FINDINGS_SCHEMA["properties"]["findings"]["items"]
    assert "vuln_class" in item["required"]
    assert "category" not in item["properties"]
