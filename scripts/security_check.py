#!/usr/bin/env python3
"""Dependency-free security regression checks for the static site."""

from __future__ import annotations

import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
HTML_FILES = sorted(ROOT.glob("*.html"))
ERRORS: list[str] = []
MAX_PAGE_ASSET_BYTES = 10 * 1024 * 1024

REQUIRED_HEADERS = {
    "Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Permissions-Policy",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
}

SECRET_PATTERNS = {
    "AWS access key": re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "GitHub token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "Google API key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "npm token": re.compile(rb"npm_[A-Za-z0-9]{20,}"),
    "Slack token": re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "Stripe secret key": re.compile(rb"sk_(?:live|test)_[0-9A-Za-z]{16,}"),
}

FORBIDDEN_SUFFIXES = {
    ".bak",
    ".db",
    ".jks",
    ".key",
    ".keystore",
    ".log",
    ".map",
    ".p12",
    ".pem",
    ".pfx",
    ".sql",
    ".sqlite",
}

FORBIDDEN_PUBLISH_SUFFIXES = FORBIDDEN_SUFFIXES | {
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".yaml",
    ".yml",
}


class SiteHTMLParser(HTMLParser):
    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.references: list[tuple[str, str, int]] = []
        self.inline_scripts: list[str] = []
        self._script_parts: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        line = self.getpos()[0]

        for attribute in ("href", "src", "data-full"):
            value = attributes.get(attribute)
            if value:
                self.references.append((attribute, value, line))

        if tag == "form":
            ERRORS.append(f"{self.path.name}:{line}: forms require a new security review")

        if tag == "a" and attributes.get("target") == "_blank":
            rel = set((attributes.get("rel") or "").split())
            if not {"noopener", "noreferrer"}.issubset(rel):
                ERRORS.append(f"{self.path.name}:{line}: target=_blank requires rel=noopener noreferrer")

        if tag == "script":
            if attributes.get("src"):
                return
            self._script_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._script_parts is not None:
            self.inline_scripts.append("".join(self._script_parts))
            self._script_parts = None

    def handle_data(self, data: str) -> None:
        if self._script_parts is not None:
            self._script_parts.append(data)


def error(message: str) -> None:
    ERRORS.append(message)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def check_tracked_files(files: list[Path]) -> None:
    for path in files:
        relative = path.relative_to(ROOT)
        lower_name = path.name.lower()

        if lower_name == ".env" or (lower_name.startswith(".env.") and lower_name != ".env.example"):
            error(f"{relative}: environment file must not be tracked")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            error(f"{relative}: sensitive or development-only file type is tracked")

        if path.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp", ".ttf"}:
            continue

        content = path.read_bytes()
        private_key_marker = b"-----BEGIN " + b"PRIVATE KEY-----"
        if private_key_marker in content:
            error(f"{relative}: private-key material detected (value redacted)")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                error(f"{relative}: {label} signature detected (value redacted)")


def load_security_policy() -> tuple[str, set[str]]:
    config_path = ROOT / "netlify.toml"
    if not config_path.exists():
        error("netlify.toml: missing Netlify security configuration")
        return "", set()

    with config_path.open("rb") as config_file:
        config = tomllib.load(config_file)

    build = config.get("build", {})
    if build.get("publish") != "dist":
        error("netlify.toml: publish directory must be the isolated dist directory")
    if build.get("command") != "python3 scripts/build_site.py":
        error("netlify.toml: unexpected production build command")

    wildcard_rules = [rule for rule in config.get("headers", []) if rule.get("for") == "/*"]
    if len(wildcard_rules) != 1:
        error("netlify.toml: expected exactly one /* header rule")
        return "", set()

    headers = wildcard_rules[0].get("values", {})
    missing_headers = REQUIRED_HEADERS - headers.keys()
    if missing_headers:
        error(f"netlify.toml: missing headers: {', '.join(sorted(missing_headers))}")

    csp = headers.get("Content-Security-Policy", "")
    script_match = re.search(r"(?:^|;)\s*script-src\s+([^;]+)", csp)
    if not script_match:
        error("netlify.toml: CSP is missing script-src")
        return csp, set()

    script_policy = script_match.group(1)
    if "'unsafe-inline'" in script_policy or "'unsafe-eval'" in script_policy:
        error("netlify.toml: script-src must not allow unsafe-inline or unsafe-eval")

    hashes = set(re.findall(r"sha256-[A-Za-z0-9+/=]+", script_policy))
    return csp, hashes


def check_publish_output() -> None:
    publish_dir = ROOT / "dist"
    if not publish_dir.is_dir() or publish_dir.is_symlink():
        error("dist: production output is missing or unsafe; run scripts/build_site.py")
        return

    source_pages = {path.name for path in HTML_FILES}
    published_pages = {path.name for path in publish_dir.glob("*.html")}
    if published_pages != source_pages:
        error("dist: published HTML pages do not match the current source pages")

    forbidden_names = {".env", ".git", ".github", ".gitignore", "netlify.toml", "scripts"}
    for path in publish_dir.rglob("*"):
        if path.is_symlink():
            error(f"{path.relative_to(ROOT)}: symlinks are forbidden in production output")
        if path.name in forbidden_names or path.name.startswith("."):
            error(f"{path.relative_to(ROOT)}: private/source path leaked into production output")
        if path.is_file() and path.suffix.lower() in FORBIDDEN_PUBLISH_SUFFIXES:
            error(f"{path.relative_to(ROOT)}: private/source file type leaked into production output")

    for source_page in HTML_FILES:
        published_page = publish_dir / source_page.name
        if published_page.is_file() and published_page.read_bytes() != source_page.read_bytes():
            error(f"dist/{source_page.name}: production page differs from source")

        if not published_page.is_file():
            continue
        source = published_page.read_text(encoding="utf-8")
        parser = SiteHTMLParser(published_page)
        parser.feed(source)
        for attribute, value, line in parser.references:
            parsed = urlsplit(value)
            if parsed.scheme or value.startswith(("#", "//")):
                continue
            target = published_page.parent / unquote(parsed.path)
            try:
                target.resolve().relative_to(publish_dir.resolve())
            except ValueError:
                error(f"dist/{source_page.name}:{line}: {attribute} escapes the publish directory")
                continue
            if parsed.path and not target.exists():
                error(f"dist/{source_page.name}:{line}: referenced file was not published: {value!r}")

        for asset_reference in re.findall(
            r"[\"']([^\"']+\.(?:jpe?g|png|webp|gif|svg|woff2?|ttf))[\"']",
            source,
            flags=re.IGNORECASE,
        ):
            parsed = urlsplit(asset_reference)
            if not parsed.scheme and not (published_page.parent / unquote(parsed.path)).is_file():
                error(f"dist/{source_page.name}: scripted asset was not published: {asset_reference!r}")


def check_reference(page: Path, attribute: str, value: str, line: int) -> None:
    parsed = urlsplit(value)
    if parsed.scheme:
        if parsed.scheme not in {"https", "mailto", "tel"}:
            error(f"{page.name}:{line}: {attribute} uses disallowed scheme {parsed.scheme!r}")
        return
    if value.startswith("//"):
        error(f"{page.name}:{line}: protocol-relative URL is not allowed")
        return
    if value.startswith("#"):
        return

    local_path = unquote(parsed.path)
    target = ROOT / local_path.lstrip("/") if local_path.startswith("/") else page.parent / local_path
    try:
        target.resolve().relative_to(ROOT.resolve())
    except ValueError:
        error(f"{page.name}:{line}: local reference escapes the repository root")
        return
    if local_path and not target.exists():
        error(f"{page.name}:{line}: missing local {attribute} target {value!r}")


def check_html(csp_hashes: set[str]) -> None:
    observed_hashes: set[str] = set()

    for page in HTML_FILES:
        source = page.read_text(encoding="utf-8")
        parser = SiteHTMLParser(page)
        parser.feed(source)
        local_assets: set[Path] = set()

        for attribute, value, line in parser.references:
            check_reference(page, attribute, value, line)
            parsed = urlsplit(value)
            if not parsed.scheme and not value.startswith(("#", "//")):
                local_assets.add(page.parent / unquote(parsed.path))

        for asset_reference in re.findall(
            r"[\"']([^\"']+\.(?:jpe?g|png|webp|gif|svg|woff2?|ttf))[\"']",
            source,
            flags=re.IGNORECASE,
        ):
            local_assets.add(page.parent / unquote(urlsplit(asset_reference).path))

        asset_bytes = sum(asset.stat().st_size for asset in local_assets if asset.is_file())
        if asset_bytes > MAX_PAGE_ASSET_BYTES:
            asset_mib = asset_bytes / (1024 * 1024)
            error(f"{page.name}: referenced assets total {asset_mib:.1f} MiB (limit is 10 MiB)")

        risky_sinks = {
            "innerHTML": r"\.innerHTML\s*=",
            "document.write": r"document\.write\s*\(",
            "eval": r"\beval\s*\(",
            "Function constructor": r"\bnew\s+Function\s*\(",
        }
        for label, pattern in risky_sinks.items():
            if re.search(pattern, source):
                error(f"{page.name}: risky DOM sink {label} requires review")

        for script_index, script in enumerate(parser.inline_scripts, start=1):
            digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
            observed_hashes.add(f"sha256-{digest}")
            syntax = subprocess.run(
                ["node", "--check", "-"],
                input=script,
                text=True,
                capture_output=True,
            )
            if syntax.returncode != 0:
                error(f"{page.name}: inline script {script_index} has invalid JavaScript syntax")

    missing_hashes = observed_hashes - csp_hashes
    stale_hashes = csp_hashes - observed_hashes
    if missing_hashes:
        error("netlify.toml: CSP does not authorize every current inline script")
    if stale_hashes:
        error("netlify.toml: CSP contains stale inline-script hashes")


def main() -> int:
    files = tracked_files()
    check_tracked_files(files)
    _csp, hashes = load_security_policy()
    check_html(hashes)
    check_publish_output()

    if ERRORS:
        for message in ERRORS:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1

    print(f"Security checks passed for {len(HTML_FILES)} HTML files and {len(files)} tracked files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
