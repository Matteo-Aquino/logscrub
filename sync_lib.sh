#!/usr/bin/env bash
# sync_lib.sh — Copy logscrub engine into TA-logscrub/lib/
# Run this whenever logscrub source files change before packaging the add-on.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/logscrub"
DST="$SCRIPT_DIR/TA-logscrub/lib/logscrub"

mkdir -p "$DST"
for f in __init__.py engine.py patterns.py handlers.py audit.py profiles.py; do
    cp "$SRC/$f" "$DST/$f"
    echo "synced: $f"
done

echo "Done. TA-logscrub/lib/logscrub is up to date."
