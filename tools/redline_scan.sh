#!/usr/bin/env bash
# redline_scan.sh — confidentiality scan for outbound content.
#
# Scans md/txt/html/tex files (or any explicitly listed file) for:
#   1. Pattern hits from tools/redline_patterns.txt (extended regex, one per
#      line; '#' starts a comment). Maintain your own list — the shipped
#      default guards against accidental secrets only.
#   2. IPv4 address literals (excluding 127.0.0.1 / 0.0.0.0 and lines that
#      mention localhost) — internal hostnames leak as IPs too easily.
#
# Usage: bash tools/redline_scan.sh <file-or-dir> [more paths...]
# Exit 0 = clean; Exit 1 = FATAL hit found. Suitable for CI.
#
# This is the public-repo copy of the scanner: it ships NO organization-
# specific pattern list. Drop your own confidentiality patterns into
# tools/redline_patterns.txt (gitignored *.local.txt variants are read as
# well) — do not commit internal identifiers just to scan for them.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
PATTERN_FILES=(
  "${REDLINE_PATTERNS:-}"
  "$HERE/redline_patterns.txt"
  "$HERE/redline_patterns.local.txt"
)

PAT_TMP="$(mktemp)"
for pf in "${PATTERN_FILES[@]}"; do
  [ -n "$pf" ] && [ -f "$pf" ] || continue
  grep -v '^[[:space:]]*#' "$pf" | grep -v '^[[:space:]]*$' >> "$PAT_TMP"
done

fatal=0

scan_file() {
  local f="$1"
  # IP address literals (internal host references)
  if grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$f" 2>/dev/null \
     | grep -vE '0\.0\.0\.0|127\.0\.0\.1|localhost' >/dev/null 2>&1; then
    echo "FATAL  $f: IP address literal:"
    grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$f" \
      | grep -vE '0\.0\.0\.0|127\.0\.0\.1|localhost' | head -5
    fatal=1
  fi
  # configured patterns
  if [ -s "$PAT_TMP" ]; then
    while IFS= read -r p; do
      if grep -nEi -- "$p" "$f" >/dev/null 2>&1; then
        echo "FATAL  $f: pattern '$p'"
        grep -nEi -- "$p" "$f" | head -5
        fatal=1
      fi
    done < "$PAT_TMP"
  fi
}

for target in "$@"; do
  if [ -d "$target" ]; then
    while IFS= read -r -d '' f; do scan_file "$f"; done \
      < <(find "$target" -type f \( -name '*.md' -o -name '*.txt' \
           -o -name '*.html' -o -name '*.tex' \) -print0)
  elif [ -f "$target" ]; then
    scan_file "$target"
  else
    echo "SKIP   $target (not found)"
  fi
done

rm -f "$PAT_TMP"
echo "---"
if [ "$fatal" -eq 1 ]; then
  echo "RESULT: FATAL red-line hits found — DO NOT RELEASE"
  exit 1
fi
echo "RESULT: clean"
exit 0
