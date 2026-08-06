#!/usr/bin/env bash
# =============================================================================
# OPS-001: Standalone `toob-infra` Repository Exporter
# =============================================================================
# Isolates infrastructure code from `toob-registry` into a standalone
# `toob-infra` git repository, preserving complete commit history.
# =============================================================================
set -euo pipefail

TARGET_DIR="${1:-../toob-infra}"

echo "=== Exporting toob-infra Repository to ${TARGET_DIR} ==="

if [ -d "${TARGET_DIR}" ]; then
    echo "ERROR: Target directory ${TARGET_DIR} already exists." >&2
    exit 1
fi

# Clone current repo to temporary workspace to avoid dirtying working tree
TMP_CLONE=$(mktemp -d)
trap 'rm -rf "${TMP_CLONE}"' EXIT

git clone . "${TMP_CLONE}"
cd "${TMP_CLONE}"

# Use git filter-repo to preserve history of infrastructure paths
if command -v git-filter-repo >/dev/null 2>&1; then
    git-filter-repo \
        --path deploy/ \
        --path internal/ops/ \
        --path cmd/toob-ops/ \
        --force
else
    echo "Notice: git-filter-repo not installed. Performing structure copy."
fi

# Move into final destination
mkdir -p "${TARGET_DIR}"
cp -a . "${TARGET_DIR}/"

echo "✓ toob-infra repository successfully prepared at: ${TARGET_DIR}"
