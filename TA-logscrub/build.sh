#!/usr/bin/env bash
# build.sh — Build, package, and (optionally) AppInspect the TA-logscrub add-on.
#
# Prerequisites:
#   pip install splunk-add-on-ucc-framework splunk-sdk pyyaml
#   pip install splunk-appinspect          ← optional, for local validation
#
# Steps performed:
#   1. Sync logscrub engine into package/lib/logscrub/
#   2. Bundle runtime dependencies (splunklib, yaml) into package/lib/
#   3. Strip .pyc / __pycache__ from lib/
#   4. Run ucc-gen build  →  output/TA-logscrub/
#   5. Create Splunkbase .tar.gz  →  output/TA-logscrub-<version>.tar.gz (with 644/755 modes)
#   6. Run splunk-appinspect (if installed)
#
# Usage:
#   ./build.sh              # build + package
#   ./build.sh --inspect    # build + package + appinspect
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RUN_INSPECT=false
for arg in "$@"; do
  [[ "$arg" == "--inspect" ]] && RUN_INSPECT=true
done

# ── Resolve version from globalConfig.json ────────────────────────────────────
VERSION="$(python3 -c "import json; print(json.load(open('globalConfig.json'))['meta']['version'])")"
echo "Building TA-logscrub v${VERSION} ..."
echo ""

# ── 1. Sync logscrub engine ───────────────────────────────────────────────────
echo "[1/7] Syncing logscrub engine → package/lib/logscrub/ ..."
SRC="../logscrub"
DST="package/lib/logscrub"
mkdir -p "$DST"
for f in __init__.py engine.py patterns.py handlers.py audit.py profiles.py; do
    cp "$SRC/$f" "$DST/$f"
done

# ── 2. Bundle runtime dependencies ───────────────────────────────────────────
# splunklib (splunk-sdk) and pyyaml must be shipped inside lib/ so the add-on
# works without requiring the admin to install packages on the search head.
echo "[2/7] Installing runtime dependencies into package/lib/ ..."
pip install --quiet --target package/lib \
    splunk-sdk \
    pyyaml

# ── 3. Strip .pyc / __pycache__ (AppInspect flags compiled bytecode) ─────────
echo "[3/7] Cleaning .pyc and __pycache__ from package/lib/ ..."
find package/lib -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find package/lib -name "*.pyc" -delete 2>/dev/null || true
# Also remove test directories shipped with dependencies (AppInspect flags them)
find package/lib -type d -name "tests"  -exec rm -rf {} + 2>/dev/null || true
find package/lib -type d -name "test"   -exec rm -rf {} + 2>/dev/null || true

# ── 4. Run ucc-gen build ──────────────────────────────────────────────────────
echo "[4/7] Running ucc-gen build ..."
# Ensure output dir is writable before ucc-gen tries to clean/recreate it
if [[ -d output/TA-logscrub ]]; then
    chmod -R u+rwX output/TA-logscrub
    rm -rf output/TA-logscrub
fi
ucc-gen build \
    --source package \
    --config globalConfig.json \
    --ta-version "${VERSION}"
# ucc-gen may exit 0 on error — check the output dir was actually created
[[ -d output/TA-logscrub ]] || { echo "ERROR: ucc-gen failed to produce output/TA-logscrub"; exit 1; }

# Patch UCC-generated restmap.conf: add python.required (AppInspect future_failure)
RESTMAP="output/TA-logscrub/default/restmap.conf"
if [[ -f "$RESTMAP" ]] && ! grep -q "python.required" "$RESTMAP"; then
    chmod u+w "$RESTMAP"
    sed -i '/\[admin_external:ta_logscrub_settings\]/a python.required = 3.13' "$RESTMAP"
    echo "  Patched restmap.conf with python.required = 3.13"
fi

# ── 5. Package as .tar.gz for Splunkbase ──────────────────────────────────────
TARBALL="output/TA-logscrub-${VERSION}.tar.gz"
echo "[5/6] Creating Splunkbase package → ${TARBALL} ..."
# --mode sets permissions inside the archive: files=644, dirs=755 (AppInspect requirement)
chmod u+rwx output/TA-logscrub
tar -czf "${TARBALL}" -C output --mode='u=rw,go=r,a+X' TA-logscrub

echo ""
echo "Build complete."
echo "  Installable add-on : output/TA-logscrub/"
echo "  Splunkbase package : ${TARBALL}"
echo ""

# ── 6. AppInspect (optional) ──────────────────────────────────────────────────
if [[ "$RUN_INSPECT" == "true" ]]; then
    echo "[6/6] Running splunk-appinspect ..."
    if ! command -v splunk-appinspect &>/dev/null; then
        echo "  splunk-appinspect not found — run:  pip install splunk-appinspect"
        exit 1
    fi
    splunk-appinspect inspect "${TARBALL}" \
        --included-tags cloud \
        --output-file output/appinspect_report.json \
        --mode precert
    echo ""
    echo "AppInspect report: output/appinspect_report.json"
    # Surface failures
    python3 - <<'PYEOF'
import json, sys
data = json.load(open("output/appinspect_report.json"))
reports = data.get("reports", [])
failures = [
    f"  [{g['name']}] {c['name']}: {c.get('description','')}"
    for r in reports
    for g in r.get("groups", [])
    for c in g.get("checks", [])
    if c.get("result") in ("failure", "error")
]
if failures:
    print(f"\n{len(failures)} check(s) FAILED:\n")
    print("\n".join(failures))
    sys.exit(1)
else:
    print("All AppInspect checks passed.")
PYEOF
else
    echo "[6/6] Skipping AppInspect (pass --inspect to enable)."
fi
