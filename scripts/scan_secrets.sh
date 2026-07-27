#!/bin/sh

set -eu

# High-confidence credential formats only. Findings report paths and revisions,
# never the matched value.
secret_pattern='(-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_(live|test)_[0-9A-Za-z]{16,}|xox[baprs]-[0-9A-Za-z-]{10,}|npm_[A-Za-z0-9]{20,})'
failed=0

scan_worktree() {
  file_list=$(mktemp)
  trap 'rm -f "$file_list"' EXIT HUP INT TERM
  git ls-files -co --exclude-standard > "$file_list"

  while IFS= read -r file; do
    case "$file" in
      *.jpg|*.jpeg|*.png|*.webp|*.ttf) continue ;;
    esac
    if grep -IlE "$secret_pattern" "$file" >/dev/null 2>&1; then
      printf 'Potential secret signature detected (value redacted): %s\n' "$file" >&2
      failed=1
    fi
  done < "$file_list"

  rm -f "$file_list"
  trap - EXIT HUP INT TERM
}

scan_revision() {
  revision=$1
  matches=$(git grep -IlE "$secret_pattern" "$revision" -- \
    ':!*.jpg' ':!*.jpeg' ':!*.png' ':!*.webp' ':!*.ttf' 2>/dev/null || true)

  if [ -n "$matches" ]; then
    printf 'Potential secret signature detected (values redacted):\n%s\n' "$matches" >&2
    failed=1
  fi
}

scan_worktree

if [ "${1:-}" = "--history" ]; then
  for revision in $(git rev-list --all --reflog); do
    scan_revision "$revision"
  done

  for blob in $(git fsck --full --unreachable --no-reflogs 2>/dev/null | awk '$2 == "blob" { print $3 }'); do
    if git cat-file blob "$blob" | grep -IqE "$secret_pattern"; then
      printf 'Potential secret signature detected in unreachable Git blob (value redacted): %s\n' "$blob" >&2
      failed=1
    fi
  done
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi

printf 'Secret scan passed.\n'
