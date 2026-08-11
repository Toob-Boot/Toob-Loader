#!/usr/bin/env bash
# =============================================================================
# Exporter for Identity, Policy & OpenFGA Files (Bash / Linux / macOS)
# =============================================================================
# Exports all source code, migration scripts, configurations, rules, and
# OpenFGA models from `identity/`, `policy/`, `shared/policy/`, and all `.fga`
# files of `toob-infra` into a single consolidated text file.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INFRA_ROOT="${WORKSPACE_ROOT}/toob-infra"

if [ ! -d "${INFRA_ROOT}" ]; then
    INFRA_ROOT="${WORKSPACE_ROOT}"
fi

OUTPUT_DIR="${1:-${WORKSPACE_ROOT}}"
OUT_FILE="${OUTPUT_DIR}/identity_and_policy_export.txt"

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUT_FILE}"

echo "=== Exporting Identity, Policy & OpenFGA Files ==="
echo "Source Root: ${INFRA_ROOT}"
echo "Output File: ${OUT_FILE}"

# Collect relative file paths matching identity/, policy/, shared/policy/, or .fga files
FILES=()
while IFS= read -r file; do
    rel="${file#${INFRA_ROOT}/}"

    # Must match identity/, policy/, shared/policy/, or .fga / fga.mod / .fga.yaml
    if [[ ! "${rel}" =~ ^(identity|policy|shared/policy)/ ]] && [[ "${rel}" != *.fga ]] && [[ "$(basename "${rel}")" != "fga.mod" ]] && [[ "${rel}" != *.fga.yaml ]]; then
        continue
    fi

    if [[ "${rel}" =~ (^|/)(\.git|\.terraform|\.cache|vendor|build|coverage|scratch|logs|_archived_scripts|_archived_workflows)/ ]]; then
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
    echo "TOOB-INFRA IDENTITY, POLICY & OPENFGA EXPORT"
    echo "Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    echo "Total Included Files: ${TOTAL_FILES}"
    echo "================================================================================"
    echo ""
    echo "COMPACT REPOSITORY FILE TREE:"
    echo "--------------------------------------------------------------------------------"
    if command -v tree >/dev/null 2>&1; then
        (cd "${INFRA_ROOT}" && tree -a -I '.git|.terraform|.cache|vendor|build|coverage|scratch|logs|*.md|go.sum|*_export.txt' --noreport)
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

echo "✓ Identity & Policy export completed successfully!"
echo "  Exported Files : ${TOTAL_FILES}"
echo "  Destination    : ${OUT_FILE}"
