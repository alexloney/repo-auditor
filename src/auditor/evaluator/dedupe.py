import re

from ..utils.filesystem import normalize_relpath

# Two findings in the same file are duplicates when their lines are within LINE_WINDOW of each
# other (or either has no line) AND their titles are similar. Category is deliberately ignored:
# the agentic scanner's categories are free text and won't match the single-file enum.
LINE_WINDOW = 10
TITLE_SIMILARITY_THRESHOLD = 0.5

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

_STOPWORDS = {
    "a", "an", "the", "in", "on", "of", "to", "for", "with", "and", "or", "is", "be",
    "at", "by", "from", "when", "if", "not", "no", "may", "can", "could", "possible",
    "potential", "missing", "bug", "issue", "error",
}

def _title_tokens(title) -> frozenset[str]:
    words = re.findall(r"[a-z0-9]+", (title or "").lower())
    # Collapse simple plurals so "handle"/"handles" match
    return frozenset(w.rstrip("s") if len(w) > 3 else w for w in words if w not in _STOPWORDS)

def _title_similarity(a: frozenset[str], b: frozenset[str]) -> float:
    """Dice coefficient over title words: 1.0 for identical word sets, 0.0 for disjoint ones."""
    if not a or not b:
        return 1.0 if a == b else 0.0
    return 2 * len(a & b) / (len(a) + len(b))

def _lines_close(a, b) -> bool:
    if not isinstance(a, int) or not isinstance(b, int):
        return True  # without both line numbers, rely on the title check alone
    return abs(a - b) <= LINE_WINDOW

def _preference(finding: dict) -> tuple:
    """Lower sorts first: higher confidence, then higher severity."""
    return (
        CONFIDENCE_RANK.get(finding.get("confidence"), 9),
        SEVERITY_RANK.get(finding.get("severity"), 9),
    )

def dedupe_findings(findings: list) -> list:
    """Merges findings that describe the same defect, keeping the best-supported copy.

    Findings are duplicates when they are in the same file, on nearby lines, and have similar
    titles. Of each duplicate group, the highest-confidence (then highest-severity) finding
    is kept; ties keep the earliest one. If other scanners reported the same defect, the kept
    finding lists them in `also_found_by`. The result is sorted by severity.
    """
    # Each entry: (finding, normalized path, title tokens)
    kept: list[tuple[dict, str, frozenset[str]]] = []
    # Scanners that reported each group, parallel to `kept`
    group_scanners: list[set[str]] = []

    for f_ in findings:
        path = normalize_relpath(f_.get("file"))
        tokens = _title_tokens(f_.get("title"))

        for i, (other, other_path, other_tokens) in enumerate(kept):
            if (path == other_path
                    and _lines_close(f_.get("line"), other.get("line"))
                    and _title_similarity(tokens, other_tokens) >= TITLE_SIMILARITY_THRESHOLD):
                if _preference(f_) < _preference(other):
                    kept[i] = (f_, path, tokens)
                if f_.get("scanner"):
                    group_scanners[i].add(f_["scanner"])
                break
        else:
            kept.append((f_, path, tokens))
            group_scanners.append({f_["scanner"]} if f_.get("scanner") else set())

    out = []
    for (f_, _, _), scanners in zip(kept, group_scanners):
        others = sorted(scanners - {f_.get("scanner")})
        if others:
            f_["also_found_by"] = others
        out.append(f_)
    out.sort(key=lambda f_: SEVERITY_RANK.get(f_.get("severity"), 9))
    return out
