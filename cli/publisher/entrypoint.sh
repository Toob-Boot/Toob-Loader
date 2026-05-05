#!/bin/bash
set -e

echo "[Publisher] Received webhook trigger from GitHub."

EVENT_FILE=$1

if [ -z "$EVENT_FILE" ] || [ ! -f "$EVENT_FILE" ]; then
    echo "[Publisher] Error: Event payload file not found."
    exit 1
fi

echo "[Publisher] Firing ephemeral Act containers for Release Pipeline..."

# Run act from the /repo directory.
# -W points to the workflow file we want to run.
# -e points to the GitHub event payload that triggered the webhook.
# --secret-file points to the .secrets file mounted into /repo.
cd /repo
act push -W .github/workflows/release.yml -e "$EVENT_FILE" --secret-file .secrets
