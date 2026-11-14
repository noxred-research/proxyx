#!/usr/bin/env python3
"""Self-hosted-only gate: every workflow job runs on the organization's self-hosted runners.

Checks, all of which must pass (exit status 0):

1. Every job in `.github/workflows/*.yml` and `*.yaml` has a `runs-on` that names the label
   `self-hosted`. Accepted forms: a string (`runs-on: self-hosted`), a flow list
   (`[self-hosted, noxred]`), a block list, and a `labels:` list inside the group form. A
   `runs-on` that only holds an expression (`${{ matrix.os }}`) or only a runner group or a
   hosted label such as `ubuntu-latest` is refused: the gate cannot see where it lands.
2. A job that calls a reusable workflow (job-level `uses:`) calls one of this repository
   (`./.github/workflows/...`), which this gate checks as well. A call of another repository's
   workflow is refused, because the callee decides where it runs.
3. Neither `.github/dependabot.yml` nor `.github/dependabot.yaml` exists. Dependabot version
   updates run on GitHub-hosted runners; dependency and base-image updates are done by
   maintainers.

The parser is line based and needs no YAML library: it reads the job keys at the job's own
indentation, which is enough for the forms above. Comments are ignored.

Usage: ci/check-self-hosted-only.py [ROOT]   (default: the repository root)
       ci/check-self-hosted-only.py --self-test   (the gate must refuse synthetic bad input)
Exit status: 0 clean, 1 on any finding. Findings print as `file:line: message`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LABEL = re.compile(r"(?<![\w-])self-hosted(?![\w-])", re.IGNORECASE)
KEY = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9_-]+|'[^']*'|\"[^\"]*\"):(?:\s+(?P<value>.*))?$")
LOCAL_CALL = re.compile(r"^\./\.github/workflows/[^\s]+\.ya?ml$")


def strip_comment(line: str) -> str:
    """Drop a trailing `# comment` that is outside quotes."""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line.rstrip()


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def check_workflow(text: str, label: str) -> list[str]:
    """Return the findings (`label:line: message`) for one workflow file."""
    lines = [strip_comment(raw) for raw in text.splitlines()]
    findings: list[str] = []

    def find(number: int, message: str) -> None:
        findings.append(f"{label}:{number}: {message}")

    jobs_at = next(
        (i for i, line in enumerate(lines) if line.startswith("jobs:") and not line[5:].strip()),
        None,
    )
    if jobs_at is None:
        # `on: workflow_call` files without jobs are not valid either; actionlint reports them.
        return findings

    # Job ids sit at the indentation of the first key below `jobs:`.
    job_indent = None
    job_starts: list[tuple[int, str]] = []
    for i in range(jobs_at + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        if job_indent is None:
            job_indent = indent_of(line)
        if indent_of(line) < job_indent:
            break
        match = KEY.match(line)
        if indent_of(line) == job_indent and match:
            job_starts.append((i, match["key"].strip("'\"")))
    if job_indent is None:
        return findings

    for n, (start, job_id) in enumerate(job_starts):
        end = job_starts[n + 1][0] if n + 1 < len(job_starts) else len(lines)
        # Stop at the first line that leaves the jobs mapping (a later top-level key).
        for i in range(start + 1, end):
            if lines[i].strip() and indent_of(lines[i]) < job_indent:
                end = i
                break
        body = [i for i in range(start + 1, end) if lines[i].strip()]
        if not body:
            find(start + 1, f"job `{job_id}` is empty")
            continue
        key_indent = indent_of(lines[body[0]])
        runs_on = uses = None
        for i in body:
            match = KEY.match(lines[i])
            if indent_of(lines[i]) != key_indent or not match:
                continue
            if match["key"] == "runs-on":
                runs_on = (i, match["value"] or "")
            elif match["key"] == "uses":
                uses = (i, (match["value"] or "").strip().strip("'\""))

        if uses is not None:
            if not LOCAL_CALL.match(uses[1]):
                find(uses[0] + 1, f"job `{job_id}` calls `{uses[1]}`; only reusable workflows of this repository are allowed")
            continue
        if runs_on is None:
            find(start + 1, f"job `{job_id}` has no `runs-on`")
            continue

        # The value is the inline text plus every following line that belongs to the key:
        # more indented lines, and `- item` lines at the key's own indentation.
        i, value = runs_on
        parts = [value]
        for j in range(i + 1, end):
            line = lines[j]
            if not line.strip():
                continue
            if indent_of(line) > key_indent or (indent_of(line) == key_indent and line.lstrip().startswith("- ")):
                parts.append(line.strip())
            else:
                break
        if not LABEL.search(" ".join(parts)):
            shown = " ".join(parts).strip() or "(empty)"
            find(i + 1, f"job `{job_id}` has `runs-on: {shown}`; it must name the `self-hosted` label")
    return findings


def check_tree(root: Path) -> list[str]:
    findings: list[str] = []
    github = root / ".github"
    for name in ("dependabot.yml", "dependabot.yaml"):
        if (github / name).exists():
            findings.append(
                f".github/{name}:1: Dependabot version updates run on GitHub-hosted runners; "
                "delete the file and update dependencies by hand"
            )
    workflows = sorted((github / "workflows").glob("*.y*ml")) if (github / "workflows").is_dir() else []
    for path in workflows:
        if path.suffix not in (".yml", ".yaml"):
            continue
        findings += check_workflow(path.read_text(encoding="utf-8"), path.relative_to(root).as_posix())
    return findings


# Synthetic workflows: (text, number of findings the gate must report).
SELF_TEST = [
    ("jobs:\n  a:\n    runs-on: [self-hosted, noxred]\n    steps: []\n", 0),
    ("jobs:\n  a:\n    runs-on: self-hosted\n    steps: []\n", 0),
    ("jobs:\n  a:\n    runs-on: \"Self-Hosted\" # comment\n    steps: []\n", 0),
    ("jobs:\n  a:\n    runs-on:\n      - self-hosted\n      - noxred\n    steps: []\n", 0),
    ("jobs:\n  a:\n    runs-on:\n    - self-hosted\n    steps: []\n", 0),
    ("jobs:\n  a:\n    runs-on:\n      group: pool\n      labels: [self-hosted, noxred]\n    steps: []\n", 0),
    ("jobs:\n  a:\n    uses: ./.github/workflows/other.yml\n", 0),
    ("jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n", 1),
    ("jobs:\n  a:\n    runs-on: [ubuntu-24.04, noxred]\n    steps: []\n", 1),
    ("jobs:\n  a:\n    runs-on: ubuntu-latest # self-hosted\n    steps: []\n", 1),
    ("jobs:\n  a:\n    runs-on: ${{ matrix.os }}\n    steps: []\n", 1),
    ("jobs:\n  a:\n    runs-on:\n      group: larger-runners\n    steps: []\n", 1),
    ("jobs:\n  a:\n    runs-on: [self-hosted]\n    steps: []\n  b:\n    runs-on: windows-latest\n    steps: []\n", 1),
    ("jobs:\n  a:\n    steps: []\n", 1),
    ("jobs:\n  a:\n    uses: someone/else/.github/workflows/ci.yml@main\n", 1),
    ("jobs:\n  a:\n    runs-on: [self-hosted]\n    steps:\n      - run: echo self-hosted\n  b:\n    runs-on: macos-latest\n", 1),
]


def self_test() -> int:
    failed = 0
    for index, (text, expected) in enumerate(SELF_TEST):
        got = check_workflow(text, f"case-{index}.yml")
        if len(got) != expected:
            print(f"self-test case {index}: expected {expected} finding(s), got {len(got)}: {got}", file=sys.stderr)
            failed += 1
    if failed:
        return 1
    print(f"check-self-hosted-only: self-test passed ({len(SELF_TEST)} cases)")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(argv[0]) if argv else Path(__file__).resolve().parent.parent
    findings = check_tree(root)
    for finding in findings:
        print(finding)
    if findings:
        print(f"check-self-hosted-only: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
