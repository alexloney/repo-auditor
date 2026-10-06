from pathlib import Path
from typing import Callable

from ..utils.evidence import coerce_line, evidence_lines, find_evidence, resolve_line

def ground_findings(target_dir: Path, findings: list[dict],
                    on_warning: Callable[[str], None] = None) -> tuple[list[dict], int, int]:
    """Checks each finding's quoted evidence against the real file.

    - Evidence found: the finding is kept, and its line is set to where the quote actually
      is (keeping the reported line if it already falls inside the quote).
    - Evidence not found: the finding is dropped as hallucinated.
    - No usable evidence, or the file can't be read: kept unchanged (e.g. ledger entries
      written before evidence was required); the critic still reviews them.

    Returns (kept_findings, dropped_count, corrected_count).
    """
    on_warning = on_warning or (lambda _: None)
    root = Path(target_dir).resolve()
    sources: dict[str, str | None] = {}
    kept, dropped, corrected = [], 0, 0

    for finding in findings:
        line = coerce_line(finding.get("line"))
        file_path = str(finding.get("file") or "").replace("\\", "/")

        if not evidence_lines(finding.get("evidence")) or not file_path:
            finding["line"] = line
            kept.append(finding)
            continue

        if file_path not in sources:
            full_path = (root / file_path).resolve()
            try:
                inside = full_path == root or root in full_path.parents
                sources[file_path] = full_path.read_text(encoding="utf-8", errors="replace") if inside else None
            except OSError:
                sources[file_path] = None
        source = sources[file_path]

        if source is None:
            finding["line"] = line
            kept.append(finding)
            continue

        spans = find_evidence(source, finding["evidence"])
        if not spans:
            dropped += 1
            on_warning(f"Dropped '{finding.get('title')}' ({file_path}): quoted evidence not found in the file")
            continue

        resolved = resolve_line(line, spans)
        if resolved != line:
            corrected += 1
        finding["line"] = resolved
        kept.append(finding)

    return kept, dropped, corrected
