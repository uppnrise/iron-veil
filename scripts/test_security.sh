#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

final_base=$(awk '
    toupper($1) == "FROM" { base = $2 }
    END { print base }
' "$repo_root/Dockerfile")

if [ "$final_base" != "scratch" ]; then
    echo "expected the final container stage to use scratch, found: $final_base" >&2
    exit 1
fi

cd "$repo_root/web"
npm audit --package-lock-only --audit-level=low
