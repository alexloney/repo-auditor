# repo-auditor

A plugin-based repository reviewer backed by a local [Ollama](https://ollama.com/) model.

Point it at a checked-out repository and it reviews the source for bugs and security
vulnerabilities, has a second "critic" pass prune false positives, and writes a Markdown report
of the findings that survive.

```powershell
repo-auditor C:\path\to\some-repo
```

Everything runs locally against your Ollama server. Nothing is executed, built or sent anywhere
else.

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
- [Development](#development)
- [Limitations](#limitations)

---

## How it works

```
                 ┌─────────────────────────────────────┐
  repo on disk → │ scanners (plugins, run in sequence) │ → findings.json  (JSONL ledger)
                 └─────────────────────────────────────┘          │
                 ┌─────────────────────────────────────┐          │
                 │ evidence → dedupe → critic → report │ ←────────┘
                 └─────────────────────────────────────┘ → report.md
```

1. **Scan.** Each selected scanner analyses the repository and appends findings to a shared
   JSON Lines ledger.
2. **Evidence check.** Each finding's quoted code is matched against the real file. Findings
   quoting code that isn't there are dropped, and line numbers are corrected (see
   [Evidence check](#evidence-check)).
3. **Dedupe.** Findings describing the same defect are merged (see [Deduplication](#deduplication)).
4. **Critic.** Each remaining finding is handed to a skeptical agent that can read and search the
   repository, and must submit a verdict: keep (optionally lowering the severity) or reject.
5. **Report.** Surviving findings are written to a Markdown report, sorted by severity.

Scanners come in two styles:

| Style | How it works | Good for |
| --- | --- | --- |
| **Per-file** (structured output) | Code selects each file and sends it to the model with a JSON schema. Every eligible file is reviewed. | Exhaustive, localized review. |
| **Agentic** (tool calling) | The model gets tools (`list_files`, `read_file`, `search_code`, …) and decides what to read, in a loop. | Cross-file reasoning, such as checking that callers match a function's contract. |

---

## Installation

Requires **Python 3.10+** and a reachable Ollama server.

```powershell
git clone <this-repo>
cd repo-auditor

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -e .
```

This installs the `repo-auditor` command. `python -m auditor` works too.

### Ollama

Pull or create the model you want to use and pass it with `--model` (default
`qwen-coder-64k:latest`). If the server isn't at `http://localhost:11434`, pass `--ollama`.

The default context settings assume a model with a **64k context window**. For a smaller model,
lower `MAX_CONTEXT` to match its real window (see [Configuration](#configuration)), otherwise
Ollama silently truncates prompts.

**Thinking models** spend part of their output budget on reasoning before they answer.
`OUTPUT_RESERVE` is the budget for both, so raise it if you see empty completions with
`done_reason=length`.

---

## Usage

```powershell
# Run every enabled scanner, then dedupe, critic and report
repo-auditor C:\path\to\repo

# Run specific scanners
repo-auditor C:\path\to\repo --scans single-file,arch

# Use a different model and server
repo-auditor C:\path\to\repo --model qwen3-coder:30b --ollama http://192.168.1.20:11434

# See which scanners are registered
repo-auditor --list
```

### CLI reference

| Argument | Default | Description |
| --- | --- | --- |
| `repo_path` | | Repository to audit. Required unless `--list` is given. |
| `--scans` | `all` | Comma-separated scanner IDs, or `all`. Unknown IDs are an error. |
| `--list` | | Print the registered scanners and exit. |
| `--model` | `qwen-coder-64k:latest` | Ollama model name. |
| `--ollama` | `http://localhost:11434` | Ollama server URL. |
| `--ledger` | `findings.json` | Ledger file, relative to the current directory. |
| `--report` | `report.md` | Report file, relative to the current directory. |
| `--extensions` | 33 common source extensions | Comma-separated extensions to audit, replacing the defaults, e.g. `.py,.go`. The leading dot is optional and case is ignored. An empty value audits every extension. |
| `--add-extensions` | | Comma-separated extensions to add to the defaults (or to `--extensions`), e.g. `yml,toml`. |
| `--skip-dirs` | `test`, `tests`, `node_modules`, `vendor`, `build`, `.venv`, … | Comma-separated directory names to skip, replacing the defaults. Matched exactly. |
| `--add-skip-dirs` | | Comma-separated directory names to skip in addition to the defaults (or to `--skip-dirs`). |
| `--max-turns` | `100` | Model turns allowed for agentic scanners. Retries after failed or empty responses don't count. |
| `--batch-max-files` | `8` | `batch` scanner: most files reviewed together in one request. |
| `--batch-max-tokens` | `40000` | `batch` scanner: most estimated tokens of code in one request. Lowered automatically if it wouldn't fit in the model's context. |
| `--timeout` | `1800` | Seconds allowed for one model request before it counts as failed and is retried. Requests aren't streamed, so this must cover a whole response, including a thinking model's reasoning. |

The exit code is `0` on success, `1` when the target doesn't exist, a scanner ID is unknown,
or the ledger can't be read, and `130` when the run is interrupted.

### Stopping a run

**Ctrl+C stops the whole run immediately**, whichever scanner, or the critic, is running. It
doesn't wait for the current model request to finish: requests run on a background thread, so
the interrupt takes effect within a fraction of a second, and the abandoned request is dropped
when the program exits. Findings already recorded stay in the ledger. No report is written for
an interrupted run.

### Enabling and disabling scanners

Scanners are discovered automatically from `src/auditor/scanners/`. To leave one out of `all`,
**prefix its module filename with an underscore** (e.g. `owasp.py` → `_owasp.py`). It can still
be run explicitly with `--scans owasp`, and `--list` marks it as disabled.

---

## Scanners

| ID | Name | Style | Focus |
| --- | --- | --- | --- |
| `single-file` | Single File Analysis | Per-file | Localized defects in one file at a time |
| `owasp` | OWASP Top 10 Analysis | Per-file | OWASP Top 10 (2021) vulnerabilities |
| `batch` | Batched Context Analysis | Per-batch | Defects between related files, reviewed together |
| `memory` | Memory Corruption Deep Scan | Per-function | Buffer overflows, use-after-free and similar (C/C++ only) |
| `arch` | Architectural Agentic Scan | Agentic | Cross-file and architectural defects |
| `taint` | Injection & Traversal Taint Scan | Agentic | SQL injection, path traversal and command injection traced from source to sink |

How they complement each other: `single-file` and `owasp` see one file with no outside context.
`batch` adds the files each file imports or is imported by, while still covering every file.
`arch` and `taint` can follow code anywhere in the repository, but the agent decides what to
read, so they don't guarantee coverage. `memory` only runs on C-family sources and does nothing
on other repositories.

### `single-file`

Reviews each eligible file in isolation with one schema-constrained call. The prompt targets
small, local defects: regex errors, malformed strings, off-by-one boundaries and local logic
flaws. Because the model sees only one file, it is told to assume imports and external functions
exist and behave correctly.

### `owasp`

Same mechanics as `single-file`, with a security prompt. Findings must map to an OWASP Top 10
(2021) category. Generic logic bugs, style and performance issues are excluded unless they
directly cause a vulnerability. Each finding carries an `owasp_category` (A01–A10) and a
`vuln_class` (e.g. `SQL injection`, `CWE-79`). Findings are always tagged category `security`.

### `batch`

Reviews groups of related files in one request, so the model can check the contracts between
them: arguments, return values, shared state and resources.

Files are grouped without any model calls. Each file is linked to the repository files that its
`import`, `from`, `#include`, `require` or `use` lines refer to, by file name (or by directory
name for `__init__.py`, `index.*` and similar). Linked files are grouped together, starting from
the most-connected ones. Files with no links are grouped with others in the same directory.
Every non-empty file lands in exactly one batch.

Each batch is limited by tokens first: at most 40,000 estimated tokens of code
(`--batch-max-tokens`). There's also a cap of 8 files (`--batch-max-files`), because with many
small files the model's attention to each one drops and it misattributes findings more often,
even when the total size is fine. Both defaults are starting points rather than measured optima,
so tune them for your model.

Findings attributed to a file that wasn't in the batch are dropped.

### `memory`

For C-family files (`.c .h .cpp .cc .cxx .hpp .hh .m .mm`, narrowed further by `--extensions`).
Each file is split into individual functions, and up to 10 at a time are sent to the model with
the file's top-of-file declarations (`#define`s, typedefs, structs), so real buffer sizes are
visible. The prompt targets exactly: buffer overflows, out-of-bounds reads and writes,
use-after-free, double-free, uninitialized memory, and integer overflow that leads to an
undersized allocation. Findings carry a `vuln_class` and are tagged category `security`.

Function extraction (`utils/code_units.py`) is structural rather than a real parser, because
C/C++ parsers need each project's include paths and compiler flags. It matches braces on a copy
of the source with comments and strings blanked out, and descends into
`class`/`struct`/`namespace`/`extern "C"` blocks. On about 2,900 real C/C++ files it extracted
roughly 34,000 functions, with the line numbers wrong for 0.2% of them. Those were mostly
constructors that brace-initialize members (`buf{x}`) and macro-generated code.

### `arch`

An agent that explores the repository with tools. It traces calls, imports and instantiations
across files to find mismatched API contracts, exceptions that escape their boundary, resource
leaks and state-management problems, and logs each one with `report_issue`. It stops when it
replies `AUDIT_COMPLETE` or reaches `--max-turns`.

When the conversation nears the context limit, the history is compacted into a summary. The
agent is then reminded of its task and given the exact list of files and line ranges it has
already read, which the read tools record as they go.

### `taint`

An agent that performs taint analysis across files for exactly three classes: **SQL injection**,
**path traversal** and **command injection**. It works backwards from the dangerous call:

1. `search_code` for candidate sinks (`execute(`, `os.system`, `shell=True`, `extractall`, …).
2. Read the enclosing function to find which variable reaches the sink.
3. Trace that variable backwards through assignments and call sites, across files, until it
   reaches a constant, a sanitizer or parameterized API, or untrusted input.

It only reports complete source-to-sink paths, with each hop in the description. This covers
the case the per-file `owasp` scanner can't: untrusted input that enters in one file and reaches
the sink in another.

---

## Output

| File | Contents |
| --- | --- |
| `findings.json` | JSON Lines ledger: one raw finding per line, appended by scanners. |
| `report.md` | The final report, with the critic's reasoning as reviewer notes. |

Both are written relative to the **current directory**, not the audited repository.

> **The ledger is not cleared between runs.** This is deliberate, for debugging the critic and
> report without re-running the scanners. Findings from earlier runs, including runs against
> other repositories, are re-verified and re-reported. Delete `findings.json` for a clean run.

### Evidence check

Every finding must quote the code it is about in an `evidence` field. Before deduplication, the
quote is matched against the real file: each quoted line must appear in a file line, in order,
skipping blank lines. Line-number gutters the model copied are ignored.

- **Found:** the finding is kept, and `line` is set to where the quote actually is. A reported
  line already inside the quote is left alone.
- **Not found:** the finding is dropped as hallucinated, with a warning.
- **No evidence, or the file can't be read:** kept unchanged, e.g. ledger entries written
  before evidence was required. The critic still reviews these.

The agentic scanners' `report_issue` tool runs the same check immediately and returns an error,
so the agent can correct its quote rather than lose the finding.

### Deduplication

Two findings count as the same defect when all of these hold:

- they are in the same file (path separators and a leading `./` are normalized);
- their lines are within 10 of each other, or either has no line number;
- their titles are similar (word overlap of at least 0.5, ignoring filler words like "the" or
  "potential").

Category is ignored, because the agentic scanner's categories are free text. Of each group, the
finding with the highest confidence, then highest severity, is kept. If other scanners reported
the same defect, they are listed in `also_found_by`.

### Critic

Each finding is checked by an agent given about 200 lines around the reported line, plus
`read_file`, `read_file_range` and `search_code`. It has 10 turns to call `submit_verdict`.
The critic **fails open**: a finding is kept if its file can't be read, the model never reaches a
verdict, or requests keep failing. A finding whose path points outside the repository is
dropped.

### Finding schema

| Field | Notes |
| --- | --- |
| `title` | Short, specific name |
| `severity` | `critical` \| `high` \| `medium` \| `low` |
| `confidence` | `high` \| `medium` \| `low` |
| `category` | `bug`, `security`, `resource-leak`, `race-condition`, `performance`, `correctness`, `api-misuse`, `other` (free text from `arch`) |
| `file` | Path relative to the repo root, with forward slashes |
| `line` | 1-indexed, or `null` if the defect isn't tied to a line. Corrected by the evidence check. |
| `evidence` | The exact line(s) of code containing the defect, quoted from the file |
| `scanner` | ID of the scanner that reported it, stamped automatically |
| `description` | Explanation of the defect |
| `steps_to_reproduce` | Optional |
| `suggested_solution` | Concrete minimal fix |
| `owasp_category` | Added by `owasp` (A01–A10:2021) |
| `vuln_class` | Added by `owasp` (free text) and `memory` (`buffer-overflow`, `use-after-free`, …) |
| `also_found_by` | Added by dedupe: other scanners that reported the same defect |
| `reviewer_notes` | Added by the critic |

---

## Configuration

Run-level options are CLI flags (above). Model-budget settings are environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `MAX_CONTEXT` | `66000` | Sent as `num_ctx`. Must not exceed the model's real context window. |
| `OUTPUT_RESERVE` | `10000` | Tokens held back for the response (including a thinking model's reasoning). Sent as `num_predict`. |
| `MAX_FILE_SIZE_BYTES` | `100000` | Larger files are skipped entirely. |

Token counts are estimated as characters ÷ 3, which over-counts slightly for source code. That
keeps prompts safely under `num_ctx` and needs no tokenizer download.

### Which files get audited

A file is reviewed when **all** of these hold:

- its extension is in `--extensions`;
- no parent directory is in `--skip-dirs`;
- its name doesn't look like a test or minified file (`test_*`, `*_test.*`, `*_tests.*`,
  `*.test.*`, `*.spec.*`, `*.min.*`);
- it is no larger than `MAX_FILE_SIZE_BYTES`.

---

## Writing a new scanner

Add a module to `src/auditor/scanners/`. Every concrete `BaseScanner` subclass defined in it is
registered by its `id`. Subclasses imported from other modules are not registered again.

`BaseScanner` provides `self.client`, `self.model`, `self.target_dir`, `self.ledger_path`,
`self.extensions`, `self.skip_dirs`, `self.max_turns`, and the `self.on_progress`,
`self.on_warning` and `self.on_error` callbacks.

### A per-file scanner

Subclass `SingleFileScanner` and override its class attributes:

```python
# src/auditor/scanners/concurrency.py
from .single_file import SingleFileScanner, make_findings_schema

class ConcurrencyScanner(SingleFileScanner):
    id = "concurrency"
    name = "Concurrency Analysis"

    SYSTEM_PROMPT = "You are reviewing a single file for data races and deadlocks. ..."
    USER_INSTRUCTION = "Audit this file snippet for real concurrency defects."
    SCHEMA = make_findings_schema(
        extra_properties={"shared_state": {"type": "string"}},
        extra_required=["shared_state"],
    )
```

### An agentic scanner

Build tools for the repository root and hand them to `run_agent_loop`:

```python
from .base import BaseScanner
from ..agent.agent import run_agent_loop
from ..agent.coverage import ReadCoverage
from ..agent.tools import (
    make_list_files_tool, make_read_file_tool, make_read_file_range_tool,
    make_search_code_tool, make_report_issue_tool,
)

class MyAgentScanner(BaseScanner):
    id = "my-agent"
    name = "My Agentic Scan"

    def run(self) -> None:
        coverage = ReadCoverage()
        root = self.target_dir
        run_agent_loop(
            client=self.client,
            model=self.model,
            system_prompt="You are ... Reply AUDIT_COMPLETE when done.",
            initial_user_prompt="Begin the audit.",
            tools=[
                make_list_files_tool(root, self.extensions, self.skip_dirs),
                make_read_file_tool(root, coverage),
                make_read_file_range_tool(root, coverage),
                make_search_code_tool(root, self.extensions, self.skip_dirs),
                make_report_issue_tool(root, self.ledger_path),
            ],
            max_turns=self.max_turns,
            coverage=coverage,
            on_progress=self.on_progress,
            on_warning=self.on_warning,
            on_error=self.on_error,
        )
```

`run_agent_loop` handles token accounting, history compaction, retries for failed and empty
responses, and the turn limit. It returns a `LoopOutcome` (`completed`, `turn_limit` or
`aborted`). Ctrl+C isn't caught; it propagates so the whole run stops. To stop on something other than a stop phrase, pass
`stop_token=None` and an `is_done` callback; the critic does this to stop once `submit_verdict`
has been called.

---

## Agent tools

Defined in `src/auditor/agent/tools.py`. Each is created by a factory bound to the repository
root:

| Tool | Description |
| --- | --- |
| `list_files(directory)` | Lists a directory, applying the extension and skip-dir filters. |
| `read_file(filepath)` | Whole file with line numbers. Refused above 15,000 estimated tokens. |
| `read_file_range(filepath, start_line, end_line)` | A line-numbered slice of a file. |
| `search_code(query, directory)` | Literal, case-sensitive text search, capped at 100 matches. |
| `report_issue(...)` | Appends a finding to the ledger (agentic scanners). |
| `submit_verdict(...)` | Records the critic's keep/reject decision (critic only). |

**Security.** The repository under audit is untrusted, and its contents go straight into the
model's context, so a malicious repository could try prompt injection to read other files. Every
path-taking tool resolves paths against the bound root and rejects anything that escapes it,
including absolute paths and `..`.

The read and search caps also stop one tool result from filling the context window.

---

## Project layout

```
src/auditor/
  __main__.py          python -m auditor
  cli.py               Argument parsing and the repo-auditor entry point
  pipeline.py          Scanner discovery and the scan → evidence → dedupe → critic → report pipeline

  agent/
    agent.py           Shared tool-calling loop, context tracking and compaction
    tools.py           Root-bound tool factories
    coverage.py        Records which files and line ranges an agent has read

  scanners/
    base.py            BaseScanner
    single_file.py     Per-file scanner template and the single-file scanner
    owasp.py           OWASP Top 10 scanner (a SingleFileScanner subclass)
    batch.py           Related files reviewed together, grouped by an import graph
    memory.py          C/C++ memory-safety review, function by function
    architectural.py   Agentic cross-file scanner
    taint.py           Agentic source-to-sink injection and traversal tracing

  evaluator/
    grounding.py       Evidence check: drops hallucinated findings, corrects lines
    dedupe.py          Merges duplicate findings
    critic.py          Agentic verification of each finding
    reporter.py        Markdown report

  utils/
    llm.py             Token estimate and schema-constrained calls with retries
    filesystem.py      File selection, line numbering and ledger writes
    code_units.py      Splits C-family source into functions (for memory)
    evidence.py        Matches a finding's quoted code against the file

test/                  pytest suite, mirroring src/auditor/
```

---

## Development

```powershell
pip install -r requirements-dev.txt
pip install -e .
pytest
```

`pytest` finds the sources through `pyproject.toml`, so no `PYTHONPATH` is needed. CI runs the
suite with coverage on Python 3.10–3.13.

---

## Limitations

- **Static analysis only.** Nothing in the audited repository is executed or modified.
- **Findings are leads, not verdicts.** Even after the critic, output is model-generated and
  will contain false positives. Review before acting. An empty report is a legitimate result.
- **Not deterministic.** Calls use temperature 0, but retries raise it, and model or server
  changes shift results.
- **Slow with `all`.** Scanners and files are processed one at a time, and with `all` every file
  is reviewed by `single-file`, `owasp` and `batch` (and by `memory` for C/C++), on top of the
  two agentic scans. For faster runs, pick scanners with `--scans`, or prefix the modules you
  don't want by default with `_`.
