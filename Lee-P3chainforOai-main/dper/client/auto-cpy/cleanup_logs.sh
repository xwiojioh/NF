#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dry=false
if [[ "${1:-}" == "--dry-run" || "${1:-}" == "-n" ]]; then
  dry=true
fi

found=false
for node in "$DIR"/dper_*; do
  [ -d "$node" ] || continue
  base=$(basename "$node")
  if [[ "$base" != dper* ]]; then
    continue
  fi
  for sub in consensusLog errLog log; do
    target="$node/log/$sub"
    if [ -d "$target" ]; then
      files=( "$target"/* )
      if [ -e "${files[0]:-}" ]; then
        found=true
        if $dry; then
          echo "DRY: would remove files in $target: ${files[*]}"
        else
          echo "Removing files in $target"
          rm -f "$target"/* || true
        fi
      else
        echo "No files in $target"
      fi
    fi
  done
done

if ! $found; then
  echo "No matching log files found."
fi

exit 0
