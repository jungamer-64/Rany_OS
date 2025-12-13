#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(pwd)"
TMPDIR="/tmp/codacy-run"
mkdir -p "$TMPDIR"
chmod 0777 "$TMPDIR" || true

JAR="$REPO_DIR/tools/codacy/codacy-analysis-cli-assembly.jar"
METRICS_LOG="$REPO_DIR/tools/codacy/metrics_no_docker.log"
RESULTS_OUT="$REPO_DIR/tools/codacy/results_metrics_no_docker.json"

echo "Running Codacy metrics with DOCKER disabled (simulate local collector path)"
echo "DOCKER_HOST will be set to an invalid socket to force local-only execution"

DOCKER_HOST=unix:///tmp/no-docker.sock java -Dfile.encoding=UTF-8 -jar "$JAR" analyze -d "$REPO_DIR" --format json --output "$RESULTS_OUT" --tool metrics --skip-uncommitted-files-check --allow-network --force-file-permissions --parallel 1 --fail-if-incomplete false --verbose --tmp-directory "$TMPDIR" > "$METRICS_LOG" 2>&1 || true

echo "Parse failed files"
bash "$REPO_DIR/tools/codacy/check_failed_files.sh" "$METRICS_LOG" "$REPO_DIR/tools/codacy/failed_read_files_no_docker.txt" || true

if [ -s "$REPO_DIR/tools/codacy/failed_read_files_no_docker.txt" ]; then
  echo "Failed files detected; collecting UTF-8 diagnostics"
  mkdir -p "$REPO_DIR/tools/codacy/utf8_issues_no_docker"
  while IFS= read -r f; do
    python3 "$REPO_DIR/tools/codacy/find_utf8_error.py" "$f" > "$REPO_DIR/tools/codacy/utf8_issues_no_docker/$(basename "$f").utf8.txt" 2>&1 || true
  done < "$REPO_DIR/tools/codacy/failed_read_files_no_docker.txt"
  echo "Diagnostics collected in $REPO_DIR/tools/codacy/utf8_issues_no_docker"
else
  echo "No failed files found in metrics_no_docker.log"
fi

echo "Complete"
exit 0
