#!/usr/bin/env python3
"""Build the static Netlify publish directory from an explicit allowlist."""

from __future__ import annotations

from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
PUBLISH_DIR = ROOT / "dist"
TEMP_DIR = ROOT / ".dist-build"

# Add a path here when introducing a new public page or asset. Directories are
# copied recursively; repository/configuration files should never be included.
PUBLISH_PATHS = (
    "index.html",
    "alt2.html",
    "calendar.html",
    "consume-new.html",
    "consume.html",
    "contact.html",
    "gallery.html",
    "mixes.html",
    "restassured.png",
    "gallery-assets",
)

FORBIDDEN_NAMES = {
    ".env",
    ".git",
    ".github",
    ".gitignore",
    ".netlify",
    "netlify.toml",
}
FORBIDDEN_SUFFIXES = {
    ".bak",
    ".db",
    ".jks",
    ".key",
    ".keystore",
    ".log",
    ".map",
    ".md",
    ".p12",
    ".pem",
    ".pfx",
    ".py",
    ".sh",
    ".sql",
    ".sqlite",
    ".toml",
    ".yaml",
    ".yml",
}


def remove_generated_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing to replace symlinked build directory: {path}")
    if path.exists():
        shutil.rmtree(path)


def validate_public_tree(path: Path) -> None:
    for candidate in (path, *path.rglob("*")):
        relative = candidate.relative_to(ROOT)
        if candidate.is_symlink():
            raise RuntimeError(f"Public allowlist must not contain symlinks: {relative}")
        if candidate.name in FORBIDDEN_NAMES or candidate.name.startswith("."):
            raise RuntimeError(f"Sensitive path is not publishable: {relative}")
        if candidate.is_file() and candidate.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise RuntimeError(f"Source/private file type is not publishable: {relative}")


def build() -> None:
    if len(PUBLISH_PATHS) != len(set(PUBLISH_PATHS)):
        raise RuntimeError("PUBLISH_PATHS contains a duplicate entry")

    remove_generated_directory(TEMP_DIR)
    TEMP_DIR.mkdir()

    try:
        for relative_name in PUBLISH_PATHS:
            relative = Path(relative_name)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"Unsafe publish path: {relative_name}")

            source = (ROOT / relative).resolve()
            try:
                source.relative_to(ROOT.resolve())
            except ValueError as exc:
                raise RuntimeError(f"Publish path escapes the repository: {relative_name}") from exc

            if not source.exists():
                raise RuntimeError(f"Allowlisted path does not exist: {relative_name}")

            validate_public_tree(source)
            destination = TEMP_DIR / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)

        remove_generated_directory(PUBLISH_DIR)
        TEMP_DIR.rename(PUBLISH_DIR)
    except Exception:
        remove_generated_directory(TEMP_DIR)
        raise

    public_files = [path for path in PUBLISH_DIR.rglob("*") if path.is_file()]
    public_bytes = sum(path.stat().st_size for path in public_files)
    print(f"Built {len(public_files)} public files ({public_bytes / (1024 * 1024):.1f} MiB) in dist/.")


if __name__ == "__main__":
    build()
