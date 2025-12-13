Codacy analysis helper scripts
===============================

This folder contains helper scripts and artifacts to run the Codacy analysis CLI locally and in CI.

Files
-----
- `ci_run_codacy.sh`: A script that runs the Codacy CLI in the current repository. It attempts to run both metrics-only and a full analysis and captures results and logs in `tools/codacy/`.
- `check_failed_files.sh`: Extracts a list of files that failed to be read by the CLI (searches for `Failed to read file` in logs) and writes them into a text file.
- `find_utf8_error.py`: A utility script that tries to find the earliest prefix where Python raises a UTF-8 decoding error (useful for debugging malformed sequences).

Notes
-----
- The Codacy CLI relies on Docker for running many of the plugins. If Docker is unavailable, the CLI may fallback to local Java-based collectors; in some circumstances these Java reading code paths can throw `java.nio.charset.MalformedInputException:` for files with multibyte characters, resulting in `Failed to read file` errors.
- For reliable CI runs, `codacy-analysis` should be executed in a Docker-enabled environment (see the GitHub Actions workflow `.github/workflows/codacy-analysis.yml`).
- If you need to run the CLI locally, ensure Docker Desktop WSL integration is enabled for the distro used (Ubuntu in this repository):

  - Docker Desktop -> Settings -> Resources -> WSL Integration -> Enable for 'Ubuntu'

How to run locally
-------------------
1. Ensure Docker is running and Java 17 is installed.
2. Run:

```
chmod +x tools/codacy/ci_run_codacy.sh
./tools/codacy/ci_run_codacy.sh
```

3. If you see `Failed to read file` entries in `tools/codacy/ci_metrics.log`, run:

```
chmod +x tools/codacy/check_failed_files.sh
./tools/codacy/check_failed_files.sh tools/codacy/ci_metrics.log
```

Reporting and next steps
------------------------
- If you persistently see `Failed to read file` even with Docker enabled, capture `tools/codacy/ci_metrics.log` and create a minimal reproduction for the Codacy team (include failing files and full logs).
