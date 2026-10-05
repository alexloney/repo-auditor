class ReadCoverage:
    """Records which files (and line ranges) an agent has read.

    Coverage is tracked in code rather than left to the model's memory, so it survives
    history compaction exactly and can be handed back to the agent afterwards.
    """

    def __init__(self):
        # relpath -> None when the whole file was read, else a list of (start, end) ranges
        self._files: dict[str, list[tuple[int, int]] | None] = {}

    def record_full(self, relpath: str) -> None:
        self._files[relpath] = None

    def record_range(self, relpath: str, start: int, end: int) -> None:
        if relpath in self._files and self._files[relpath] is None:
            return  # already read in full
        self._files.setdefault(relpath, []).append((start, end))

    def __len__(self) -> int:
        return len(self._files)

    def summary(self) -> str:
        """One line per file read, e.g. '- src/a.py (full)' or '- src/b.py (lines 1-80, 200-260)'."""
        lines = []
        for relpath in sorted(self._files):
            ranges = self._files[relpath]
            if ranges is None:
                lines.append(f"- {relpath} (full)")
            else:
                spans = ", ".join(f"{s}-{e}" for s, e in _merge_ranges(ranges))
                lines.append(f"- {relpath} (lines {spans})")
        return "\n".join(lines)

def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
