#!/usr/bin/env python3
"""Provenance gate: fail when a tracked file carries a reference that must not be public.

ProxyX does not reference the names of systems or organisations its code came from. Those
names cannot be listed here without defeating the rule, so the gate stores only the SHA-256
of each lowercase token and compares every word of every tracked file against them. Words are
split on non-alphanumerics and on lower-to-upper camel-case boundaries, so `foo_bar`,
`FooBar`, `foo-bar` and `FOO_BAR` are all checked.

Further rules reject:

* internal ticket identifiers (`ABC-123` style references with the known tracker prefixes) and
  citations of internal design records or review findings, which carry no meaning for readers
  of the public repository;
* `third-party-name`: names of third-party products, services and vendors (proxy providers, IP
  reputation and echo services, anti-bot and CAPTCHA vendors, LLM vendors and tools, browser
  automation libraries, search engines). Integrations keep working under neutral names. A line
  carrying the marker `wire-compat` (an exact string an external service or client needs: a
  default host, a request or reply field, a command) or `detection-data` (a string matched on
  target sites) is allowed, and so is the line directly below a marked line, for a statement a
  raw string or formatter keeps from carrying a trailing comment. Dependency manifests, `use`
  and `import` lines, license attributions, `deny.toml`, lock files and this file are exempt;
* `host-path`: absolute paths of a developer machine (a tmp, cache or workspace directory
  under `/data`, or a user's home directory);
* `privileged-pr-trigger`: the privileged fork-PR workflow trigger, which this repository does
  not use.

Usage: ci/lint-provenance.py [PATH ...]   (default: every file `git ls-files` lists)
Exit status: 0 clean, 1 on any hit. Hits print as `file:line: [rule]` without the matched
text, so CI logs never spell the retired names either.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

# SHA-256 of retired lowercase tokens. To add one: printf '%s' token | sha256sum
RETIRED = {
    "4730c11d802c77e0b63e17e5e095598b42ae56caf25f3af6212fbcee9a44ab41",
    "034bca3116c2da587f536842b2984a3d9b154222a5218e795f640573bb5d9477",
    "307f9dc2407ef963e5fb553f6b1e31525b0311c5e0f2883644aeea17a86864b2",
    "739e72f2db16302b3d58893083364d942bd22727938b316be2ae6c5a12b342fc",
    "77f1d1c04d32a84a569b4aed05ef453ec4f464fcac98de97bb2f5033df2c4a04",
}
TICKET = re.compile(r"\b(?:SCN|INFRA|P-INFRA|SRE|DEV|REC)-\d{2,5}\b")
# Citations of internal design records and review findings (record or finding id + number).
CITATION = re.compile(r"\b(?:ADR|BO|CR|AR-S|W5|D-OBS|D-R|D-W|D-S|D-API|D2-API)-\d{1,4}\b")
WORD = re.compile(r"[A-Za-z0-9]+")
CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
SKIP_SUFFIXES = {".png", ".jpg", ".ico", ".der", ".woff", ".woff2", ".gz", ".zip"}
SKIP_NAMES = {"Cargo.lock", "package-lock.json", "uv.lock"}

# Third-party products, services and vendors (matched case-insensitively, anywhere in a line).
THIRD_PARTY = re.compile(
    r"oxylabs|bright[ _-]?data|luminati|iproyal|webshare|decodo|smartproxy|soax|netnut|geonode"
    r"|rayobyte|zyte|scrapingbee|scraperapi|apify"
    r"|ipqs|ipqualityscore|abuseipdb|scamalytics|x4bnet|ipinfo|ifconfig\.co|ifconfig_co|ipify"
    r"|maxmind|ip2location"
    r"|cloudflare|datadome|perimeterx|akamai|imperva|incapsula|sucuri|kasada"
    r"|recaptcha|hcaptcha|turnstile|capsolver|2captcha"
    r"|openai|anthropic|chatgpt|claude|ollama|vllm|openrouter|gemini|mistral|deepseek|windsurf"
    r"|playwright|puppeteer|selenium|patchright|chromium"
    r"|cf-mitigated|cf-chl|px-captcha|captcha-delivery|superproxy|cdn-cgi"
    r"|google|gstatic|stripe",
    re.IGNORECASE,
)
MARKER = re.compile(r"wire-compat|detection-data")
# `use` and `import` lines name the dependency they load.
IMPORT = re.compile(r"^\s*(?:(?:pub(?:\([a-z]+\))?\s+)?use\s|extern\s+crate\s|import\s|from\s+\S+\s+import\s)")
# Dependency manifests, license attributions and this file.
EXEMPT_NAMES = {
    "THIRD_PARTY_NOTICES.md",
    "CODE_OF_CONDUCT.md",
    "deny.toml",
    "Cargo.toml",
    "pyproject.toml",
    "package.json",
    "lint-provenance.py",
}
HOST_PATH = re.compile(r"/data/(?:tmp|cache|workspace)|/home/[a-z]")
PRIVILEGED_TRIGGER = re.compile(r"pull_request_targe[t]")


def tokens(line: str):
    for word in WORD.findall(line):
        yield word.lower()
        for part in CAMEL.findall(word):
            yield part.lower()


def retired(token: str) -> bool:
    return hashlib.sha256(token.encode()).hexdigest() in RETIRED


def third_party_exempt(path: Path) -> bool:
    name = path.name
    return name in EXEMPT_NAMES or name.startswith("LICENSE") or re.fullmatch(r"requirements.*\.txt", name) is not None


def files(args: list[str]) -> list[Path]:
    if args:
        return [Path(a) for a in args]
    out = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
    return [Path(p) for p in out.decode().split("\0") if p]


def main(argv: list[str]) -> int:
    hits = 0
    for path in files(argv):
        if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lines = text.splitlines()
        marked = [bool(MARKER.search(line)) for line in lines]
        check_third_party = not third_party_exempt(path)
        for number, line in enumerate(lines, 1):
            if check_third_party and THIRD_PARTY.search(line) and not IMPORT.match(line):
                if not (marked[number - 1] or (number > 1 and marked[number - 2])):
                    print(f"{path}:{number}: [third-party-name]")
                    hits += 1
            if HOST_PATH.search(line):
                print(f"{path}:{number}: [host-path]")
                hits += 1
            if PRIVILEGED_TRIGGER.search(line):
                print(f"{path}:{number}: [privileged-pr-trigger]")
                hits += 1
            if any(retired(t) for t in tokens(line)):
                print(f"{path}:{number}: [retired-name]")
                hits += 1
            if TICKET.search(line):
                print(f"{path}:{number}: [internal-ticket]")
                hits += 1
            if CITATION.search(line):
                print(f"{path}:{number}: [internal-citation]")
                hits += 1
        if any(retired(t) for t in tokens(str(path))):
            print(f"{path}: [retired-name in path]")
            hits += 1
        if check_third_party and THIRD_PARTY.search(str(path)):
            print(f"{path}: [third-party-name in path]")
            hits += 1
    if hits:
        print(f"lint-provenance: {hits} hit(s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
