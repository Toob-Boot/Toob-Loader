#!/usr/bin/env bash
# =============================================================================
# Full Repository Exporter for toob-infra (Bash / Linux / macOS)
# =============================================================================
# Exports ALL source code, deployment manifests (deploy/), configuration, scripts,
# and policy files of `toob-infra` into a single consolidated text file.
# Excludes `registry/` layer (per instruction) and .md documentation files.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INFRA_ROOT="${WORKSPACE_ROOT}/toob-infra"

if [ ! -d "${INFRA_ROOT}" ]; then
    INFRA_ROOT="${WORKSPACE_ROOT}"
fi

OUTPUT_DIR="${1:-${WORKSPACE_ROOT}}"
OUT_FILE="${OUTPUT_DIR}/toob_infra_full_export.txt"

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUT_FILE}"

echo "=== Exporting Full toob-infra Repository (Excluding registry/) ==="
echo "Source Root: ${INFRA_ROOT}"
echo "Output File: ${OUT_FILE}"

# Collect relative file paths excluding registry/, .md, binaries, .git, build dirs
FILES=()
while IFS= read -r file; do
    rel="${file#${INFRA_ROOT}/}"
    if [[ "${rel}" =~ (^|/)(registry|\.git|\.terraform|\.cache|vendor|build|coverage|scratch|logs|_archived_scripts|_archived_workflows)/ ]]; then
        continue
    fi
    if [[ "${rel}" =~ \.(exe|zip|tar|gz|db|png|jpg|pdf|bin|elf|md)$ ]]; then
        continue
    fi
    if [[ "$(basename "${rel}")" == "go.sum" ]] || [[ "${rel}" == *"_export.txt"* ]] || [[ "${rel}" == *"_tree.txt"* ]]; then
        continue
    fi
    FILES+=("${rel}")
done < <(find "${INFRA_ROOT}" -type f | sort)

TOTAL_FILES=${#FILES[@]}
echo "Found ${TOTAL_FILES} matching files."

# 1. Generate Header & Tree
{
    echo "================================================================================"
    echo "TOOB-INFRA FULL REPOSITORY EXPORT (EXCLUDING REGISTRY/)"
    echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    echo "Total Included Files: ${TOTAL_FILES}"
    echo "================================================================================"
    echo ""
    echo "COMPACT REPOSITORY FILE TREE:"
    echo "--------------------------------------------------------------------------------"
    if command -v tree >/dev/null 2>&1; then
        (cd "${INFRA_ROOT}" && tree -a -I 'registry|.git|.terraform|.cache|vendor|build|coverage|scratch|logs|*.md|go.sum|*_export.txt' --noreport)
    else
        for f in "${FILES[@]}"; do
            echo "  - toob-infra/${f}"
        done
    fi
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

echo "✓ Full toob-infra export (without registry/) completed successfully!"
echo "  Exported Files : ${TOTAL_FILES}"
echo "  Destination    : ${OUT_FILE}"
