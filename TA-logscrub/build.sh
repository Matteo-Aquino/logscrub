#!/usr/bin/env bash
# build.sh — Build the TA-logscrub Splunk add-on using ucc-gen.
#
# Prerequisites:
#   pip install splunk-add-on-ucc-framework
#
# Output:
#   output/TA-logscrub/   ← installable add-on (drop into $SPLUNK_HOME/etc/apps/)
#   output/TA-logscrub-*.tar.gz  ← Splunkbase package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Sync engine library ───────────────────────────────────────────────────────
echo "Syncing logscrub engine into package/lib/ ..."
SRC="../logscrub"
DST="package/lib/logscrub"
mkdir -p "$DST"
for f in __init__.py engine.py patterns.py handlers.py audit.py profiles.py; do
    cp "$SRC/$f" "$DST/$f"
done
echo "Engine synced."

# ── Build with ucc-gen ────────────────────────────────────────────────────────
echo "Running ucc-gen build ..."
ucc-gen build \
    --source package \
    --config globalConfig.json \
    --ta-version "$(python3 -c "import json; print(json.load(open('globalConfig.json'))['meta']['version'])")"

echo ""
echo "Build complete."
echo "Installable add-on: output/TA-logscrub/"
echo ""
ls output/
