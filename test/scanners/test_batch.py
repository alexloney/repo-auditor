from unittest.mock import MagicMock, patch

from auditor.scanners.batch import BatchScanner, build_import_graph, plan_batches

def test_import_graph_links_python_js_and_c_imports():
    contents = {
        "pkg/parser.py": "from pkg.lexer import tokenize\n",
        "pkg/lexer.py": "import re\n",
        "web/app.js": "const db = require('./db');\n",
        "web/db.js": "module.exports = {};\n",
        "src/buf.c": '#include "buf.h"\n',
        "src/buf.h": "void f(void);\n",
        "other.py": "x = 'parser'  # mentions parser outside an import\n",
    }
    edges = build_import_graph(contents)

    assert edges["pkg/parser.py"] == {"pkg/lexer.py"}
    assert edges["pkg/lexer.py"] == {"pkg/parser.py"}  # undirected
    assert edges["web/app.js"] == {"web/db.js"}
    assert edges["src/buf.c"] == {"src/buf.h"}
    assert edges["other.py"] == set()

def test_import_graph_uses_directory_name_for_package_entry_points():
    contents = {"utils/__init__.py": "X = 1\n", "app.py": "import utils\n"}
    assert build_import_graph(contents)["app.py"] == {"utils/__init__.py"}

def test_plan_batches_groups_related_files_and_covers_everything():
    files = ["a.py", "b.py", "c.py", "lib/x.py", "lib/y.py"]
    edges = {"a.py": {"b.py"}, "b.py": {"a.py"}, "c.py": set(), "lib/x.py": set(), "lib/y.py": set()}
    sizes = dict.fromkeys(files, 10)

    batches = plan_batches(files, edges, sizes, max_files=2)

    assert ["a.py", "b.py"] in batches
    assert ["lib/x.py", "lib/y.py"] in batches  # unrelated files packed by directory
    assert sorted(f for b in batches for f in b) == sorted(files)

def test_plan_batches_respects_size_and_token_limits():
    files = ["hub.py", "a.py", "b.py", "c.py"]
    edges = {"hub.py": {"a.py", "b.py", "c.py"}, "a.py": {"hub.py"}, "b.py": {"hub.py"}, "c.py": {"hub.py"}}
    sizes = {"hub.py": 10, "a.py": 10, "b.py": 100, "c.py": 10}

    batches = plan_batches(files, edges, sizes, max_files=3, max_tokens=50)

    assert all(len(b) <= 3 for b in batches)
    assert all(sum(sizes[f] for f in b) <= 50 for b in batches if len(b) > 1)
    assert sorted(f for b in batches for f in b) == sorted(files)

@patch("auditor.scanners.batch.append_finding")
@patch("auditor.scanners.batch.call_json")
def test_batch_scanner_keeps_only_findings_for_files_in_the_batch(mock_call_json, mock_append, tmp_path):
    (tmp_path / "a.py").write_text("import b\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")  # empty: never sent
    mock_call_json.return_value = {"findings": [
        {"title": "Real", "file": "./b.py"},
        {"title": "Hallucinated", "file": "c.py"},
    ]}
    scanner = BatchScanner(client=MagicMock(), model="m", target_dir=tmp_path,
                           ledger_path=tmp_path / "l.json", extensions=[".py"])

    scanner.run()

    mock_call_json.assert_called_once()
    user = mock_call_json.call_args[0][3]
    assert "START FILE: a.py" in user and "START FILE: b.py" in user
    assert "__init__.py" not in user
    assert [c[0][1]["title"] for c in mock_append.call_args_list] == ["Real"]
    assert mock_append.call_args[0][1]["file"] == "b.py"
