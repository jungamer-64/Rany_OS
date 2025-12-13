#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(pwd)"
TMPDIR="/tmp/codacy-run"
mkdir -p "$TMPDIR"
chmod 0777 "$TMPDIR" || true

JAR="$REPO_DIR/tools/codacy/codacy-analysis-cli-assembly.jar"
METRICS_OUT="$REPO_DIR/tools/codacy/results_metrics_ci.json"
FULL_OUT="$REPO_DIR/tools/codacy/results_full_ci.json"
METRICS_LOG="$REPO_DIR/tools/codacy/ci_metrics.log"
FULL_LOG="$REPO_DIR/tools/codacy/ci_full.log"
JAVA_OPTS="-Dfile.encoding=UTF-8"

echo "Codacy CI run starting (Jar=$JAR)"
echo "TMPDIR=$TMPDIR"
echo "METRICS_LOG=$METRICS_LOG"
echo "FULL_LOG=$FULL_LOG"

if ! command -v java >/dev/null 2>&1; then
  echo "ERROR: java not found. Install Java 17 (Temurin / OpenJDK)"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "WARNING: Docker not available — Codacy may run in local mode and produce different results."
fi

echo "Running metrics (Docker-enabled if available)..."
java $JAVA_OPTS -jar "$JAR" analyze -d "$REPO_DIR" --format json --output "$METRICS_OUT" --tool metrics --skip-uncommitted-files-check --allow-network --force-file-permissions --parallel 1 --fail-if-incomplete false --verbose --tmp-directory "$TMPDIR" > "$METRICS_LOG" 2>&1 || true

echo "Running full analysis (Docker-enabled if available)..."
java $JAVA_OPTS -jar "$JAR" analyze -d "$REPO_DIR" --format json --output "$FULL_OUT" --skip-uncommitted-files-check --allow-network --force-file-permissions --parallel 1 --fail-if-incomplete false --verbose --tmp-directory "$TMPDIR" > "$FULL_LOG" 2>&1 || true

echo "Codacy CI run finished"
echo "Metrics log: $METRICS_LOG"
echo "Full log: $FULL_LOG"

# Parse the logs for any "Failed to read file" entries and prepare UTF-8 diagnostics
mkdir -p "$REPO_DIR/tools/codacy/utf8_issues"
bash "$REPO_DIR/tools/codacy/check_failed_files.sh" "$METRICS_LOG" "$REPO_DIR/tools/codacy/failed_read_files_metrics.txt" || true
bash "$REPO_DIR/tools/codacy/check_failed_files.sh" "$FULL_LOG" "$REPO_DIR/tools/codacy/failed_read_files_full.txt" || true

for f in $(cat "$REPO_DIR/tools/codacy/failed_read_files_metrics.txt" 2>/dev/null || true); do
  # Run the helper to try and find UTF-8 decoding issues using Python
  python3 "$REPO_DIR/tools/codacy/find_utf8_error.py" "$f" > "$REPO_DIR/tools/codacy/utf8_issues/$(basename "$f").metrics.utf8.txt" 2>&1 || true
done
for f in $(cat "$REPO_DIR/tools/codacy/failed_read_files_full.txt" 2>/dev/null || true); do
  python3 "$REPO_DIR/tools/codacy/find_utf8_error.py" "$f" > "$REPO_DIR/tools/codacy/utf8_issues/$(basename "$f").full.utf8.txt" 2>&1 || true
done

echo "Failed read files: $REPO_DIR/tools/codacy/failed_read_files_metrics.txt, $REPO_DIR/tools/codacy/failed_read_files_full.txt"
echo "UTF8 diagnostics collected in $REPO_DIR/tools/codacy/utf8_issues/ (if any)"

# If we have the Java reproducer, run chunked-decode comparisons on failing files
if [ -f "$REPO_DIR/tools/codacy/java_repro/ChunkDecodeCompare.java" ] && command -v java >/dev/null 2>&1 && command -v javac >/dev/null 2>&1; then
  echo "Compiling Java reproducer..."
  javac "$REPO_DIR/tools/codacy/java_repro/ChunkDecodeCompare.java" -d "$REPO_DIR/tools/codacy/java_repro" || true
  for f in $(cat "$REPO_DIR/tools/codacy/failed_read_files_metrics.txt" 2>/dev/null || true); do
    for cs in 4 8 16 32; do
      out="$REPO_DIR/tools/codacy/utf8_issues/$(basename "$f").metrics.chunk${cs}.compare.txt"
      echo "Running chunk-compare on $f (chunk=$cs) -> $out"
      java -cp "$REPO_DIR/tools/codacy/java_repro" ChunkDecodeCompare "$f" "$cs" > "$out" 2>&1 || true
    done
  done
  for f in $(cat "$REPO_DIR/tools/codacy/failed_read_files_full.txt" 2>/dev/null || true); do
    for cs in 4 8 16 32; do
      out="$REPO_DIR/tools/codacy/utf8_issues/$(basename "$f").full.chunk${cs}.compare.txt"
      echo "Running chunk-compare on $f (chunk=$cs) -> $out"
      java -cp "$REPO_DIR/tools/codacy/java_repro" ChunkDecodeCompare "$f" "$cs" > "$out" 2>&1 || true
    done
  done
fi

exit 0
