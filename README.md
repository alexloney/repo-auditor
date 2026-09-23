# repo-auditor

An autonomous, plugin-based repository reviewer backed by a local [Ollama](https://ollama.com/) LLM.

Point it at a checked-out repository and it will read the source, hunt for defects and
vulnerabilities, aggressively prune false positives, and emit a Markdown report of findings
worth reviewing and turning into merge requests.

```powershell
python main.py C:\path\to\some-repo
```

---

## Contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Scanners](#scanners)
- [Output](#output)
- [Configuration](#configuration)
- [Writing a new scanner](#writing-a-new-scanner)
- [Agent tools](#agent-tools)
- [Project layout](#project-layout)
- [Design notes and limitations](#design-notes-and-limitations)

---

## How it works

The pipeline has two stages: **scan**, then **evaluate**.

```
                 ┌──────────────────────────────────────┐
  repo on disk → │  scanners/  (plugins, run in order)  │ → findings.json (JSONL ledger)
                 └──────────────────────────────────────┘
                                                              │
                 ┌──────────────────────────────────────┐     │
                 │  evaluator.py                        │ ←───┘
                 │   dedupe → LLM critic → report       │ → report.md
                 └──────────────────────────────────────┘
```

1. **Scan.** Each selected scanner plugin analyses the repository and appends findings to a
   shared append-only JSONL ledger (`findings.json`, written into the target repo).
2. **Evaluate.** After all scanners finish, `evaluator.py` deduplicates the ledger, sends each
   surviving finding back to the LLM as a hostile "critic" pass to prune hallucinations and
   nitpicks, then writes a human-readable `report.md`.

The evaluation pass always runs, regardless of which scanners were selected.

### Two scanner styles

Scanners come in two flavours, and both are first-class:

| Style | How it works | Best for |
| --- | --- | --- |
| **Push model** (structured output) | The driver code selects files, slices them into bounded chunks, and *pushes* each chunk to the LLM with a JSON schema. Deterministic coverage. | Systematic, exhaustive review where you want every file looked at. |
| **Pull model** (agentic tool-calling) | The LLM is given tools (`list_files`, `search_code`, `read_file`, …) and *pulls* whatever context it decides it needs, in a loop. | Cross-file reasoning: tracing a variable backwards through call sites. |

---

## Installation

Requires **Python 3.10+** (the code uses `X | None` type syntax) and a reachable Ollama server.

```powershell
git clone <this-repo>
cd repo-auditor

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install ollama
pip install tiktoken   # optional, see below
```

**`tiktoken` is optional.** It is used for token estimation when packing prompts. If it is not
installed, every call site falls back to a `len(text) // 4` heuristic. Installing it makes the
context-budget maths meaningfully more accurate, which reduces truncated/empty LLM responses.

### Ollama

The Ollama host is currently hardcoded in `main.py`:

```python
client = ollama.Client(host="http://192.168.86.5:11434")
```

Change that line to point at your own server (e.g. `http://localhost:11434`). Then pull or
create the model named by the `MODEL` environment variable (default `qwen-coder-64k:latest`):

```powershell
ollama pull qwen2.5-coder:32b
$env:MODEL = "qwen2.5-coder:32b"
```

> The default model name implies a **64k context window**. If you point `MODEL` at a model with
> a smaller real context, lower `MAX_CONTEXT` to match or you will get empty completions.

---

## Usage

```powershell
# Run every enabled scanner, then the evaluation pass
python main.py C:\path\to\repo

# Run specific scanners
python main.py C:\path\to\repo --scans single-file,owasp

# See which plugins are registered
python main.py --list
```

### CLI reference

| Argument | Description |
| --- | --- |
| `repo_path` | Target repository directory. Required unless `--list` is given. |
| `--scans` | Comma-separated scanner IDs, or `all` (default). |
| `--list` | Print the registered plugins and exit. |

### Enabling and disabling scanners

Plugins are discovered automatically from `scanners/`. To stop one running as part of `all`,
**prefix its module filename with an underscore**:

```powershell
Rename-Item scanners\taint.py scanners\_taint.py
```

Disabled plugins are still loaded and can be invoked explicitly by ID (`--scans taint`), which
is convenient for iterating on a scanner you've otherwise parked. `--list` marks them:

```
Available scan plugins:
  batch        Batched Context Analysis
  memory       Memory Corruption Deep Scan
  owasp        OWASP Top 10 Scan
  shallow      Shallow Agentic Scan
  single-file  Single File Analysis
  taint        Injection & Traversal Taint Scan  (disabled: module name starts with '_')
```

---

## Scanners

| ID | Name | Model | Focus |
| --- | --- | --- | --- |
| `single-file` | Single File Analysis | Push | Localized defects in one file at a time |
| `batch` | Batched Context Analysis | Push | Cross-module defects in clusters of related files |
| `owasp` | OWASP Top 10 Scan | Push | OWASP Top 10 (2021) vulnerability classes |
| `memory` | Memory Corruption Deep Scan | Push | Buffer overflows, OOB access, use-after-free (C/C++) |
| `taint` | Injection & Traversal Taint Scan | Pull | SQLi, path traversal, command injection |
| `shallow` | Shallow Agentic Scan | Pull | Free-form exploratory bug hunting |

### `single-file` — Single File Analysis

Reviews each eligible file in isolation with one schema-constrained call. The prompt is tuned
for microscopic, localized defects: regex errors, malformed strings, off-by-one boundaries, and
localized logic flaws. Because the model sees no other file, it is instructed to assume all
imports and external functions exist and behave correctly.

### `batch` — Batched Context Analysis

A two-phase pass:

1. **Planner.** The LLM is shown file paths plus their first few imports and asked to cluster
   related files into batches of up to `MAX_FILES_PER_BATCH`. Planning runs in windows of
   `PLANNER_WINDOW` files, because the planner has to echo back every path it is shown and one
   giant request would blow the output budget. The plan is then reconciled against the real file
   list — hallucinated paths are dropped and forgotten files are swept into sequential batches.
2. **Review.** Each cluster is sent as one prompt, so the model can verify cross-module imports,
   signatures, and contracts. Findings whose `file` field doesn't match a file actually present
   in that batch are discarded.

### `owasp` — OWASP Top 10 Scan

Per-file review constrained to an `owasp_category` enum (A01–A10:2021). The prompt forbids
generic logic bugs, style, and performance issues unless they directly produce a vulnerability,
and instructs the model to treat third-party library code as correct — only flagging insecure
*usage* of it. Findings are tagged `category: "security"`.

### `memory` — Memory Corruption Deep Scan

A push-model scanner for manually memory-managed languages. It structurally decomposes C-family
sources into individual **function units** and pushes small groups of them
(`MAX_UNITS_PER_REQUEST`, default 10) to the model, alongside the file's top-of-file preamble so
that `#define`s, typedefs, and struct definitions with real buffer sizes are visible.

Targets buffer overflows, out-of-bounds writes/reads, use-after-free, double-free, uninitialized
memory, and integer overflow leading to undersized allocations.

Only C-family extensions are scanned (`.c .h .cpp .cc .cxx .hpp .hh .m .mm`).

### `taint` — Injection & Traversal Taint Scan

An agentic scanner that performs interprocedural taint analysis for exactly three classes: **SQL
injection**, **path traversal**, and **command injection**. It works sink-first:

1. `search_code` for candidate sinks (`execute(`, `os.system`, `shell=True`, `extractall`, …).
2. `read_file` / `read_file_range` to inspect the enclosing function.
3. Trace the tainted variable *backwards* through assignments and call sites across files until
   it reaches a literal, a sanitizer/parameterized API, or a genuine untrusted source.

It is instructed to report only complete, end-to-end source→sink paths and to document the hops.

### `shallow` — Shallow Agentic Scan

The original exploratory agent. Wanders the repository with the same toolset looking for
definitive localized bugs. Broader but less directed than `taint`.

---

## Output

Both artifacts are written **into the target repository directory**:

| File | Contents |
| --- | --- |
| `findings.json` | Append-only JSONL ledger, one raw finding per line. Written by scanners. |
| `report.md` | Final human-readable report. Written by the evaluator. |

> `findings.json` is **append-only and is not cleared between runs.** Delete it if you want a
> clean slate, otherwise findings from previous runs are re-evaluated and re-reported.

### The evaluation pass

`evaluator.py` does three things:

1. **Dedupe.** Findings are grouped by `(file, category, line // 10)` — the line bucketing
   catches the same defect reported on slightly different lines by different scanners. The
   highest-confidence entry in each group wins.
2. **Critic pass.** Each surviving finding is sent back to the LLM together with a ±100-line
   window of the real file, under a deliberately hostile system prompt that prunes
   hallucinations, context-dependent guesses, and stylistic nitpicks. The critic can also
   *downgrade* an inflated severity. Findings whose file cannot be read, or where the critic
   call fails, are kept — failures fail open.
3. **Report.** Deterministic Markdown generation (no LLM formatting call), grouped and sorted by
   severity, including the critic's reasoning as reviewer notes.

### Finding schema

Scanners append objects with these fields:

| Field | Notes |
| --- | --- |
| `title` | Short, specific name |
| `severity` | `critical` \| `high` \| `medium` \| `low` |
| `confidence` | `high` \| `medium` \| `low` |
| `category` | `bug`, `security`, `resource-leak`, `race-condition`, … |
| `file` | Path relative to the repo root |
| `line` | 1-indexed, or `null` |
| `description` | Explanation of the defect |
| `steps_to_reproduce` | Optional |
| `suggested_solution` | Concrete minimal fix |
| `owasp_category` | Added by `owasp` (A01–A10:2021) |
| `vuln_class` | Added by `memory` (`buffer-overflow`, `use-after-free`, …) |
| `reviewer_notes` | Added by the evaluator's critic pass |

---

## Configuration

All configuration is via environment variables. There is no config file.

### Model and context

| Variable | Default | Description |
| --- | --- | --- |
| `MODEL` | `qwen-coder-64k:latest` | Ollama model name. |
| `MAX_CONTEXT` | `66000` | Passed as `num_ctx`. Must not exceed the model's real window. |
| `OUTPUT_RESERVE` | `10000` | Tokens held back from `num_ctx` for the response, and used as `num_predict`. |

### File selection

| Variable | Default | Description |
| --- | --- | --- |
| `MAX_FILES_PER_REPO` | `256` | Cap on files considered per scan. |
| `MAX_FILE_SIZE_BYTES` | `100000` | Files larger than this are skipped entirely. |
| `TARGET_FILE_SIZE` | `15000` | Files are prioritized by proximity to this size. |

### Batching

| Variable | Default | Description |
| --- | --- | --- |
| `MAX_FILES_PER_BATCH` | `4` | Files per cluster in the `batch` scanner. |
| `MAX_BATCH_TOKENS` | `45000` | Hard ceiling on a batch/chunk prompt. |
| `PLANNER_WINDOW` | `40` | Files shown to the batch planner per request. |
| `MAX_UNITS_PER_REQUEST` | `10` | Functions per request in the `memory` scanner. |

### Prompt overrides

Every scanner's system prompt can be replaced without touching code:

`SINGLE_FILE_PROMPT`, `BATCH_FILE_PROMPT`, `PLANNER_SYSTEM_PROMPT`, `OWASP_SYSTEM_PROMPT`,
`MEMORY_SYSTEM_PROMPT`, `TAINT_SYSTEM_PROMPT`, `CRITIC_SYSTEM_PROMPT`.

### Which files get audited

A file is eligible when **all** of the following hold:

- Its extension is in `LANG_EXT` (Python, C/C++, JS/TS/JSX/TSX, Vue, PHP, Java, Kotlin, Go,
  Rust, Ruby, C#, Swift, Objective-C/C++, Scala, Perl, Shell, Lua, Dart).
- No parent directory is in `SKIP_DIRS` (`tests`, `node_modules`, `vendor`, `build`, `dist`,
  `.venv`, `third_party`, `generated`, …).
- The filename does not contain `test` or `min`.
- It is under `MAX_FILE_SIZE_BYTES`.

Edit `LANG_EXT` / `SKIP_DIRS` in `scanners/common.py` to change this.

---

## Writing a new scanner

Drop a module into `scanners/`. Anything subclassing `BaseScanner` is registered automatically
by `id` — no manual registration required.

```python
# scanners/my_scan.py
from .base import BaseScanner
from .common import MODEL, FINDINGS_SCHEMA, pick_files, number_lines, call_json, append_finding

SYSTEM_PROMPT = "You are a ..."

class MyScanner(BaseScanner):
    id = "my-scan"              # --scans my-scan
    name = "My Custom Scan"     # shown in --list and run headers
    model = MODEL

    def run(self) -> None:
        for relpath in pick_files(self.target_dir):
            content = (self.target_dir / relpath).read_text(encoding="utf-8", errors="replace")
            user = f"File: {relpath}\n\n{number_lines(content)}"

            data = call_json(self.client, self.model, SYSTEM_PROMPT, user, FINDINGS_SCHEMA)
            for finding in data.get("findings", []):
                finding["file"] = relpath
                append_finding(self.ledger_path, finding)
```

`BaseScanner.__init__` gives you `self.client` (Ollama client), `self.target_dir` (resolved
`Path`), and `self.ledger_path`.

### Helpers in `scanners/common.py`

| Helper | Purpose |
| --- | --- |
| `pick_files(target_dir, extensions=None)` | Eligible, size-prioritized relative paths. |
| `number_lines(content)` | Renders a line-number gutter so the model cites real lines. |
| `call_json(client, model, system, user, schema)` | Schema-constrained call with retries. |
| `append_finding(ledger_path, finding)` | Appends one JSONL record. |
| `estimate_tokens(text)` | `tiktoken` if available, else a length heuristic. |
| `FINDINGS_SCHEMA`, `OWASP_FINDINGS_SCHEMA`, `MEMORY_FINDINGS_SCHEMA` | Response schemas. |

`call_json` rejects an over-budget prompt up front, sets `num_predict`, raises a descriptive
error on empty completions (including Ollama's `done_reason`), strips stray ```` ```json ````
fences, and escalates temperature across retries so a retry isn't a deterministic replay of the
same failure.

### Writing an agentic scanner

Use `run_agent_loop` from `scanners/agent_loop.py` — don't hand-roll the loop:

```python
from .base import BaseScanner
from .agent_loop import run_agent_loop
from .common import MODEL
from agent.tools import list_files, read_file, read_file_range, search_code, report_issue

class MyAgentScanner(BaseScanner):
    id = "my-agent"
    name = "My Agentic Scan"
    model = MODEL

    def run(self) -> None:
        run_agent_loop(
            client=self.client,
            model=self.model,
            target_dir=self.target_dir,
            ledger_path=self.ledger_path,
            system_prompt=SYSTEM_PROMPT,
            initial_user_prompt="Begin the audit...",
            tools=[list_files, read_file, read_file_range, search_code, report_issue],
            label="My Agent",
            max_turns=80,
        )
```

The loop handles `chdir` into the target, wiring `AUDIT_LEDGER_PATH` for `report_issue`, token
accounting (including tool-call arguments), LLM-based history compaction when the context fills
up, empty-completion recovery, turn limits, and `Ctrl+C`.

---

## Agent tools

Available to agentic scanners, defined in `agent/tools.py`:

| Tool | Description |
| --- | --- |
| `list_files(directory)` | List a directory. |
| `read_file(filepath)` | Whole file, refused above `MAX_READ_TOKENS` (15000). |
| `read_file_range(filepath, start_line, end_line)` | Line-numbered slice of a large file. |
| `search_code(query, directory)` | Literal text search, capped at `MAX_SEARCH_RESULTS` (100). |
| `report_issue(...)` | Append a finding to the ledger. |

**Security note.** The repository being audited is untrusted input, and its contents are fed
into the model — a malicious repo could attempt prompt injection to make the agent read
arbitrary files. All path-taking tools resolve through `_resolve_within_root()`, which confines
access to the target repository root and rejects absolute paths and `..` traversal.

The read and search caps exist for a practical reason too: unbounded tool output floods the
conversation, exhausts the context window, and causes the model to return empty completions.

---

## Project layout

```
main.py                  CLI entry point, plugin discovery, orchestration
evaluator.py             Dedupe → LLM critic pass → report.md
README.md

agent/
  __init__.py            Re-exports the tool functions
  tools.py               Sandboxed tools exposed to agentic scanners

scanners/
  base.py                BaseScanner ABC
  common.py              Config, schemas, file selection, call_json, helpers
  agent_loop.py          Reusable tool-calling loop for agentic scanners
  code_units.py          C-family source → function units (for the memory scanner)

  single_file.py         Push  — per-file localized defects
  batch.py               Push  — LLM-planned clusters of related files
  owasp.py               Push  — OWASP Top 10
  memory.py              Push  — memory corruption, function-level
  taint.py               Pull  — SQLi / traversal / command injection
  shallow.py             Pull  — exploratory bug hunting
```

---

## Design notes and limitations

**Function extraction is structural, not a real AST.** `scanners/code_units.py` splits C-family
code by brace/paren matching over a copy of the source with comments and string literals masked
out, recursing into `class`/`struct`/`namespace` bodies. Real C/C++ parsers (libclang,
tree-sitter) need per-repo include paths and compile flags to parse unpreprocessed source, which
isn't available when auditing an arbitrary clone — so this trades a little accuracy for working
everywhere with no native dependency. Measured on a large real C++ codebase: 1403 functions
extracted with 3 line-number misalignments.

**Static analysis only.** Nothing is executed, built, or run. The tool never writes to the
repository under audit except for `findings.json` and `report.md`.

**Findings are leads, not verdicts.** Even after the critic pass, output is LLM-generated and
will contain false positives. Review before acting. An empty report is a legitimate result — the
prompts are deliberately tuned to suppress stylistic noise.

**Results are not deterministic.** Calls use `temperature: 0.0`, but retries escalate
temperature, and model/server changes will shift output.

**Known rough edges:**

- The Ollama host is hardcoded in `main.py` rather than configurable.
- Scanners run sequentially; a full `all` run over a large repository is slow.
- `findings.json` accumulates across runs unless manually deleted.
- The `memory` scanner is C-family only and silently does nothing on other repositories.