"""Dependency-free structural decomposition of C-family source into function units.

Real AST parsers for C/C++ (libclang, tree-sitter) need per-repo include paths and
compile flags to work on unpreprocessed code, so this uses brace/paren matching over
a comment- and string-masked copy of the source instead.
"""
import re
from dataclasses import dataclass

# Keywords that introduce a brace block which is not a function body.
_NON_FUNCTION_KEYWORDS = {
    "if", "else", "for", "while", "switch", "do", "try", "catch", "return",
    "class", "struct", "enum", "union", "namespace", "typedef", "extern",
    "template", "using", "public", "private", "protected", "friend",
}

_FUNCTION_HEADER_RE = re.compile(r"(~?\w+)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?$", re.DOTALL)


@dataclass
class CodeUnit:
    name: str
    start_line: int
    end_line: int
    text: str


def mask_code(source: str) -> str:
    """Returns source with comments and string/char literal contents blanked out.

    Positions and line breaks are preserved so offsets map back to the original text.
    """
    out = list(source)
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]

        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue

        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
            continue

        if ch in "\"'":
            quote = ch
            i += 1
            while i < n:
                if source[i] == "\\":
                    out[i] = " "
                    if i + 1 < n and source[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if source[i] == quote:
                    out[i] = " "
                    i += 1
                    break
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            continue

        i += 1

    return "".join(out)


_ACCESS_LABEL_RE = re.compile(r"^\s*(?:public|private|protected|signals|(?:public|private|protected)\s+slots|slots)\s*:", re.MULTILINE)


def _looks_like_function(header: str) -> bool:
    header = _ACCESS_LABEL_RE.sub(" ", header).strip()
    if not header or "(" not in header or ")" not in header:
        return False

    # Reject control-flow / type-declaration blocks.
    first_word = re.match(r"\s*(\w+)", header)
    if first_word and first_word.group(1) in _NON_FUNCTION_KEYWORDS:
        return False

    match = _FUNCTION_HEADER_RE.search(header)
    if not match:
        return False
    return match.group(1) not in _NON_FUNCTION_KEYWORDS


_CONTAINER_RE = re.compile(r"\b(class|struct|union|namespace)\b")


def _is_container(header: str) -> bool:
    """True for class/struct/union/namespace blocks, whose bodies hold nested member functions."""
    header = _ACCESS_LABEL_RE.sub(" ", header).strip()
    if not _CONTAINER_RE.search(header):
        return False
    # A constructor initializer list (`Foo::Foo(...) : base_(x)`) is a function, not a container.
    return not _FUNCTION_HEADER_RE.search(header)


def extract_functions(source: str) -> list:
    """Splits C-family source into function definitions, including class/namespace members."""
    masked = mask_code(source)
    line_starts = [0]
    for idx, ch in enumerate(masked):
        if ch == "\n":
            line_starts.append(idx + 1)

    def line_of(offset: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    units = []

    def scan(start: int, end: int) -> None:
        i = start
        block_start = start
        depth = 0

        while i < end:
            ch = masked[i]

            if ch == "{":
                if depth == 0:
                    header = source[block_start:i]
                    close = _match_brace(masked, i)

                    if close is not None and _is_container(header):
                        scan(i + 1, close)
                        i = close + 1
                        block_start = i
                        continue

                    if close is not None and _looks_like_function(header):
                        start_offset = block_start
                        # Skip any access-specifier label that precedes a member function.
                        labels = list(_ACCESS_LABEL_RE.finditer(header))
                        if labels:
                            start_offset = block_start + labels[-1].end()
                        while start_offset < len(source) and source[start_offset] in " \t\r\n":
                            start_offset += 1
                        # Snap to the start of the line so the rendered gutter numbers line up exactly.
                        line_begin = source.rfind("\n", 0, start_offset) + 1
                        if source[line_begin:start_offset].strip() == "":
                            start_offset = line_begin
                        name_match = _FUNCTION_HEADER_RE.search(header.strip())
                        units.append(CodeUnit(
                            name=name_match.group(1) if name_match else "<anonymous>",
                            start_line=line_of(start_offset),
                            end_line=line_of(close),
                            text=source[start_offset:close + 1],
                        ))
                        i = close + 1
                        block_start = i
                        continue
                depth += 1
                i += 1
                continue

            if ch == "}":
                depth = max(0, depth - 1)
                i += 1
                if depth == 0:
                    block_start = i
                continue

            if ch == ";" and depth == 0:
                i += 1
                block_start = i
                continue

            i += 1

    scan(0, len(masked))
    units.sort(key=lambda u: u.start_line)
    return units


def _match_brace(masked: str, open_idx: int):
    depth = 0
    for i in range(open_idx, len(masked)):
        if masked[i] == "{":
            depth += 1
        elif masked[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def file_preamble(source: str, units: list, max_lines: int = 80) -> str:
    """Returns the top-of-file region (includes, typedefs, struct and buffer-size defs)."""
    first_line = min((u.start_line for u in units), default=len(source.splitlines()) + 1)
    lines = source.splitlines()[: min(first_line - 1, max_lines)]
    return "\n".join(lines)
