from auditor.utils.evidence import coerce_line, evidence_lines, find_evidence, resolve_line

SOURCE = "def f(x):\n    if x:\n\n        return x / 0\n    return 1\n"

def test_evidence_lines_strips_gutters_fences_and_ellipses():
    quote = "```python\n   2 |     if x:\n...\n   4 |         return x / 0\n```"
    assert evidence_lines(quote) == ["if x:", "return x / 0"]

def test_evidence_lines_rejects_non_strings():
    assert evidence_lines(None) == []
    assert evidence_lines(42) == []

def test_find_evidence_single_line():
    assert find_evidence(SOURCE, "return x / 0") == [(4, 4)]

def test_find_evidence_partial_line_and_whitespace_differences():
    assert find_evidence(SOURCE, "return   x/0") == []          # tokens must match, not just characters
    assert find_evidence(SOURCE, "x / 0") == [(4, 4)]            # part of a line is enough

def test_find_evidence_multi_line_skips_blank_lines():
    assert find_evidence(SOURCE, "if x:\n    return x / 0") == [(2, 4)]

def test_find_evidence_not_found():
    assert find_evidence(SOURCE, "eval(user_input)") == []
    assert find_evidence(SOURCE, "") == []

def test_find_evidence_multiple_matches():
    assert find_evidence("a = 1\nb = 2\na = 1\n", "a = 1") == [(1, 1), (3, 3)]

def test_resolve_line_keeps_line_inside_span():
    assert resolve_line(3, [(2, 4)]) == 3

def test_resolve_line_picks_nearest_span():
    assert resolve_line(9, [(1, 1), (8, 8), (20, 20)]) == 8
    assert resolve_line(None, [(5, 6), (9, 9)]) == 5

def test_coerce_line():
    assert coerce_line(12) == 12
    assert coerce_line(" 12 ") == 12
    assert coerce_line(0) is None
    assert coerce_line(-3) is None
    assert coerce_line("n/a") is None
    assert coerce_line(None) is None
    assert coerce_line(True) is None
