#!/usr/bin/env bash
# =============================================================================
# Mini-Exporter for OpenFGA Model & Test Files (.fga, fga.mod, .fga.yaml)
# =============================================================================
# Exports all OpenFGA authorization models, module definitions, and test suites
# from `policy/model` and `policy/tests` into a single text file.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INFRA_ROOT="${WORKSPACE_ROOT}/toob-infra"

if [ ! -d "${INFRA_ROOT}" ]; then
    INFRA_ROOT="${WORKSPACE_ROOT}"
fi

OUTPUT_DIR="${1:-${WORKSPACE_ROOT}}"
OUT_FILE="${OUTPUT_DIR}/fga_files_export.txt"

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUT_FILE}"

echo "=== Exporting OpenFGA Model & Test Files ==="
echo "Source Root: ${INFRA_ROOT}"
echo "Output File: ${OUT_FILE}"

# Collect relative file paths for .fga, fga.mod, and .fga.yaml
FILES=()
while IFS= read -r file; do
    rel="${file#${INFRA_ROOT}/}"
    FILES+=("${rel}")
done < <(find "${INFRA_ROOT}/policy" -type f \( -name "*.fga" -o -name "fga.mod" -o -name "*.fga.yaml" \) | sort)

TOTAL_FILES=${#FILES[@]}
echo "Found ${TOTAL_FILES} matching FGA files."

# 1. Generate Header & Tree
{
    echo "================================================================================"
    echo "OPENFGA MODEL & TEST FILES EXPORT (.fga, fga.mod, .fga.yaml)"
    echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    echo "Total Included Files: ${TOTAL_FILES}"
    echo "================================================================================"
    echo ""
    echo "FGA FILE TREE OVERVIEW:"
    echo "--------------------------------------------------------------------------------"
    for f in "${FILES[@]}"; do
        echo "  - toob-infra/${f}"
    done
    echo "--------------------------------------------------------------------------------"
    echo ""
} > "${OUT_FILE}"

# 2. Append File Contents
for rel in "${FILES[@]}"; do
    full_path="${INFRA_ROOT}/${rel}"
    {
        echo ""
        echo "================================================================================"
        echo "FILE: toob-infra/${rel}"
        echo "================================================================================"
        if [ -s "${full_path}" ]; then
            cat "${full_path}"
        fi
    } >> "${OUT_FILE}"
done

echo "✓ OpenFGA export completed successfully!"
echo "  Exported Files : ${TOTAL_FILES}"
echo "  Destination    : ${OUT_FILE}"
