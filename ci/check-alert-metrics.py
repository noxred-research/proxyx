#!/usr/bin/env python3
"""Check the monitoring assets against the metric documentation and the runbooks.

Checks, all of which must pass (exit status 0):

1. Every metric name used in an alert or recording rule expression
   (deploy/monitoring/prometheus-rules.yml), in a dashboard panel expression or in a dashboard
   template variable query (deploy/monitoring/grafana/*.json) is documented in
   docs/metrics/*.md, or is listed in deploy/monitoring/contract-metrics.txt, or is a recording
   rule defined in the rules file, or is the scrape built-in `up`. A histogram's `_bucket`,
   `_count` and `_sum` series count as documented when the histogram is.
2. Every runbook docs/runbooks/NNN-*.md is the `runbook_url` target of at least one alert.
3. Every alert has a unique name, a `severity` of critical or warning, a `role` label and the
   annotations `summary`, `description` and `runbook_url`; every `runbook_url` ends in an
   existing runbook file, or in docs/monitoring.md with an anchor that is one of its headings.
4. Every alert name appears in docs/monitoring.md.
5. Dashboard JSON parses, panel ids are unique, a datasource variable DS_PROMETHEUS exists.

Usage: ci/check-alert-metrics.py          (run from the repository root)
Needs PyYAML (`pip install pyyaml`).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("check-alert-metrics: PyYAML is required (pip install pyyaml)")

ROOT = Path(__file__).resolve().parent.parent
MON = ROOT / "deploy" / "monitoring"
RULES = MON / "prometheus-rules.yml"
CONTRACT = MON / "contract-metrics.txt"
DASHBOARDS = sorted((MON / "grafana").glob("*.json"))
METRIC_DOCS = sorted((ROOT / "docs" / "metrics").glob("*.md"))
RUNBOOKS = sorted(
    p for p in (ROOT / "docs" / "runbooks").glob("*.md") if re.match(r"\d{3}-", p.name)
)
MONITORING_DOC = ROOT / "docs" / "monitoring.md"

BUILTIN_SERIES = {"up"}
HISTOGRAM_SUFFIXES = ("_bucket", "_count", "_sum")
SEVERITIES = {"critical", "warning"}
REQUIRED_ANNOTATIONS = ("summary", "description", "runbook_url")

# PromQL words that are not metric names.
KEYWORDS = {
    "and", "or", "unless", "by", "without", "on", "ignoring", "group_left", "group_right",
    "offset", "bool", "inf", "nan", "start", "end", "atan2",
}
NAME_RE = re.compile(r"(?<![\w.:$])[A-Za-z_:][A-Za-z0-9_:]*(?![\w:])")
DOC_HEADING_RE = re.compile(r"^###\s+`([a-z][a-z0-9_]*)`\s*$")
DOC_TYPE_RE = re.compile(r"^-\s+\*\*Type:\*\*\s+(\w+)")
DOC_TABLE_RE = re.compile(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|\s*(\w+)\s*\|")


def documented_metrics() -> dict[str, str]:
    """Return metric name -> type from docs/metrics/*.md (type is '' when unknown)."""
    found: dict[str, str] = {}
    for doc in METRIC_DOCS:
        current = None
        for line in doc.read_text(encoding="utf-8").splitlines():
            if m := DOC_HEADING_RE.match(line):
                current = m.group(1)
                found.setdefault(current, "")
            elif current and (m := DOC_TYPE_RE.match(line)):
                found[current] = m.group(1)
                current = None
            elif m := DOC_TABLE_RE.match(line):
                found[m.group(1)] = m.group(2)
    return found


def contract_metrics() -> set[str]:
    names = set()
    for line in CONTRACT.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(line)
    return names


def metric_names(expr: str) -> set[str]:
    """Metric (and recorded series) names in a PromQL expression."""
    expr = re.sub(r'"(?:[^"\\]|\\.)*"', '""', expr)
    expr = re.sub(r"'(?:[^'\\]|\\.)*'", "''", expr)
    expr = re.sub(r"\$\{?\w+\}?", "1", expr)  # Grafana variables
    expr = re.sub(r"\{[^{}]*\}", "", expr)  # label matchers
    expr = re.sub(r"\[[^\]]*\]", "", expr)  # range selectors
    expr = re.sub(
        r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)", "", expr
    )
    names = set()
    for m in NAME_RE.finditer(expr):
        word = m.group(0)
        if word.lower() in KEYWORDS:
            continue
        if re.match(r"\s*\(", expr[m.end():]):  # function call
            continue
        names.add(word)
    return names


def alert_and_record_rules(rules_doc) -> list[dict]:
    return [r for g in rules_doc["groups"] for r in g["rules"]]


def github_slug(heading: str) -> str:
    slug = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return slug.replace(" ", "-")


def monitoring_anchors() -> set[str]:
    anchors = set()
    for line in MONITORING_DOC.read_text(encoding="utf-8").splitlines():
        if m := re.match(r"^#{1,6}\s+(.*?)\s*$", line):
            anchors.add(github_slug(m.group(1)))
    return anchors


def dashboard_exprs(node, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "expr" and isinstance(value, str):
                out.append(value)
            elif key == "query" and isinstance(value, str) and "label_values" in value:
                m = re.match(r"\s*label_values\((.*),\s*\w+\s*\)\s*$", value)
                out.append(m.group(1) if m else value)
            else:
                dashboard_exprs(value, out)
    elif isinstance(node, list):
        for item in node:
            dashboard_exprs(item, out)


def panel_ids(node, out: list[int]) -> None:
    if isinstance(node, dict):
        if "id" in node and "gridPos" in node:
            out.append(node["id"])
        for value in node.values():
            panel_ids(value, out)
    elif isinstance(node, list):
        for item in node:
            panel_ids(item, out)


def main() -> int:
    errors: list[str] = []
    docs = documented_metrics()
    contract = contract_metrics()
    rules_doc = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    rules = alert_and_record_rules(rules_doc)
    recorded = {r["record"] for r in rules if "record" in r}

    def known(name: str) -> bool:
        if name in recorded or name in BUILTIN_SERIES or name in contract or name in docs:
            return True
        for suffix in HISTOGRAM_SUFFIXES:
            base = name[: -len(suffix)]
            if name.endswith(suffix) and docs.get(base) == "histogram":
                return True
        return False

    def check_expr(where: str, expr: str) -> None:
        for name in sorted(metric_names(expr)):
            if not known(name):
                errors.append(f"{where}: metric `{name}` is not documented in docs/metrics/*.md or contract-metrics.txt")

    # 1. metric names in rules and dashboards
    for rule in rules:
        label = rule.get("alert") or rule.get("record")
        check_expr(f"{RULES.name}:{label}", rule["expr"])

    # 3. alert structure
    anchors = monitoring_anchors()
    runbook_targets: set[str] = set()
    seen: set[str] = set()
    for rule in rules:
        name = rule.get("alert")
        if not name:
            continue
        if name in seen:
            errors.append(f"alert {name} is defined twice")
        seen.add(name)
        labels = rule.get("labels", {})
        notes = rule.get("annotations", {})
        if labels.get("severity") not in SEVERITIES:
            errors.append(f"alert {name}: severity must be one of {sorted(SEVERITIES)}")
        if not labels.get("role"):
            errors.append(f"alert {name}: missing role label")
        for key in REQUIRED_ANNOTATIONS:
            if not notes.get(key):
                errors.append(f"alert {name}: missing annotation {key}")
        url = notes.get("runbook_url", "")
        path, _, anchor = url.partition("#")
        m = re.search(r"/blob/main/(docs/.+\.md)$", path)
        if not m:
            errors.append(f"alert {name}: runbook_url is not a docs/*.md blob URL: {url}")
            continue
        target = m.group(1)
        if not (ROOT / target).is_file():
            errors.append(f"alert {name}: runbook_url target {target} does not exist")
        if target == "docs/monitoring.md":
            if anchor not in anchors:
                errors.append(f"alert {name}: anchor #{anchor} is not a heading of docs/monitoring.md")
        elif anchor:
            errors.append(f"alert {name}: runbook anchors are not supported: {url}")
        runbook_targets.add(target)

    # 2. every runbook is referenced
    for book in RUNBOOKS:
        rel = f"docs/runbooks/{book.name}"
        if rel not in runbook_targets:
            errors.append(f"runbook {rel} is not the runbook_url of any alert")

    # 4. alert names appear in the monitoring page
    doc_text = MONITORING_DOC.read_text(encoding="utf-8")
    for name in sorted(seen):
        if f"`{name}`" not in doc_text:
            errors.append(f"alert {name} is not listed in docs/monitoring.md")

    # 5. dashboards
    if not DASHBOARDS:
        errors.append("no dashboard JSON found under deploy/monitoring/grafana")
    for path in DASHBOARDS:
        try:
            dash = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        ids: list[int] = []
        panel_ids(dash, ids)
        if len(ids) != len(set(ids)):
            errors.append(f"{path.name}: duplicate panel ids")
        variables = {v.get("name") for v in dash.get("templating", {}).get("list", [])}
        if "DS_PROMETHEUS" not in variables:
            errors.append(f"{path.name}: no DS_PROMETHEUS datasource variable")
        exprs: list[str] = []
        dashboard_exprs(dash, exprs)
        if not exprs:
            errors.append(f"{path.name}: no panel expressions")
        for expr in exprs:
            check_expr(f"{path.name}", expr)

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print(f"check-alert-metrics: {len(errors)} problem(s)", file=sys.stderr)
        return 1
    print(
        f"check-alert-metrics: ok ({len(seen)} alerts, {len(recorded)} recording rules, "
        f"{len(RUNBOOKS)} runbooks, {len(DASHBOARDS)} dashboard(s), {len(docs)} documented metrics)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
