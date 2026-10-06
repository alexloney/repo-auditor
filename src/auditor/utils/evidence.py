"""Locating a finding's quoted `evidence` in the real file.

Scanners must quote the code a finding is about. Matching that quote against the file is a
cheap, deterministic check: a quote that isn't in the file means the model invented the code,
and a quote that is found pins down the line even when the model's line number is missing or off.
"""
import re

# The model sees line-numbered code ("  42 | x = 1") and sometimes copies the gutter.
_GUTTER_RE = re.compile(r"^\s*\d+\s*\|\s?")

def _normalize(text: str) -> str:
    return " ".join(text.split())

def evidence_lines(evidence) -> list[str]:
    """The meaningful, whitespace-normalized lines of a quote (gutters, fences and ellipses removed)."""
    if not isinstance(evidence, str):
        return []
    lines = []
    for raw in evidence.splitlines():
        line = _normalize(_GUTTER_RE.sub("", raw, count=1))
        if not line or line.startswith("```") or line in ("...", "…"):
            continue
        lines.append(line)
    return lines

def find_evidence(source: str, evidence) -> list[tuple[int, int]]:
    """Returns the (start_line, end_line) spans, 1-indexed, where the quote appears in source.

    Each quoted line must be contained in a file line, and multi-line quotes must match
    consecutive non-blank lines, so a model quoting part of a line or skipping a blank line
    still matches.
    """
    quote = evidence_lines(evidence)
    if not quote:
        return []

    file_lines = [(i + 1, _normalize(text)) for i, text in enumerate(source.splitlines())]
    non_blank = [(n, text) for n, text in file_lines if text]

    spans = []
    for start in range(len(non_blank) - len(quote) + 1):
        if all(quote[k] in non_blank[start + k][1] for k in range(len(quote))):
            spans.append((non_blank[start][0], non_blank[start + len(quote) - 1][0]))
    return spans

def resolve_line(line, spans: list[tuple[int, int]]) -> int:
    """Keeps the reported line if it falls inside a matched span, else uses the nearest span's start."""
    if isinstance(line, int) and any(start <= line <= end for start, end in spans):
        return line
    if not isinstance(line, int):
        return spans[0][0]
    return min(spans, key=lambda span: abs(span[0] - line))[0]

def coerce_line(line) -> int | None:
    """Models sometimes send line numbers as strings ("42") or 0/negative placeholders."""
    if isinstance(line, str) and line.strip().isdigit():
        line = int(line.strip())
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    return line
