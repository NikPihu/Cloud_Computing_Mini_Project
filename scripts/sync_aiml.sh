#!/bin/bash
# Re-copy the ML engine from a local clone of the AIML mini project, then rebuild the image.
#   bash scripts/sync_aiml.sh ../AIML_Mini_Project_AIT
set -euo pipefail
SRC=${1:?path to AIML_Mini_Project_AIT clone}
DEST="$(dirname "$0")/../aiml"
rm -rf "$DEST/nids" && cp -r "$SRC/nids" "$DEST/nids"
cp "$SRC/config/nsl_kdd.yaml" "$DEST/config/"
cp "$SRC/data/sample/demo_traffic.csv" "$DEST/data/sample/"
find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
echo "Synced from $(git -C "$SRC" rev-parse --short HEAD). Now: docker compose up -d --build"
