# DriverCell / LiveUpdate Manual QEMU Runbook

This runbook validates DriverCell-first `cell.*` commands and LiveUpdate behavior
on QEMU using the `driver_cell_probe` fixture cells.

## Prerequisites

- Nightly toolchain from `rust-toolchain.toml` (includes `rust-src`)
- `x86_64-exorust-cell.json` (repo-local cell target spec for `cdylib` fixtures)
- Build kernel with `qemu-test-export` when using `cell.debug_fault(...)`

## Build Fixtures

```bash
scripts/build_runtime_boot_artifacts.sh --profile debug
```

Generated artifacts:

- `target/x86_64-exorust/debug/boot_artifacts/drivers/driver_cell_probe.cell`
- `target/x86_64-exorust/debug/boot_artifacts/drivers/driver_cell_probe_pci.cell`
- `target/x86_64-exorust/debug/boot_artifacts/cells/driver_cell_probe_v1.cell`
- `target/x86_64-exorust/debug/boot_artifacts/cells/driver_cell_probe_v2.cell`
- `target/x86_64-exorust/debug/cells/driver_cell_probe_v1.cell`
- `target/x86_64-exorust/debug/cells/driver_cell_probe_v2.cell`

## Launch QEMU (interactive ExoShell)

```bash
./scripts/run.sh --serial stdio --monitor --tcg
```

Shell mode selection via cmdline:

```bash
# default (recommended): shell=console
./scripts/run.sh --serial stdio --monitor --tcg --cmdline "shell=console"

# serial-only interactive shell
./scripts/run.sh --serial stdio --monitor --tcg --cmdline "shell=serial"
```

Notes:
- Canonical key is `shell=console|serial|both|off`.
- `console=serial|both` is still accepted as a compatibility fallback.

Confirm startup logs mention:

- `Loading driver Cells from boot artifacts...`
- `Deployed ... Cell(s) to /cells`
- `Loaded driver cell 'driver_cell_probe' as dcell=...`

## ExoShell Checks

1. Preflight

```text
fs.entries("/cells")
cell.list()
cell.info(<dcell_id>)
cell.graph()
cell.inspect_artifact("/cells/driver_cell_probe_v1.cell")
cell.epoch_status()
```

Expected:
- `driver_cell_probe` exists
- `cell.list()` returns structured `Array<Map>`
- `cell.info(<dcell_id>)` contains `driver_cell.state = Running`
- `driver_cell.hot_swap_state = Idle`
- `driver_cell.loader_cell_id` and `driver_cell.domain_id` are populated
- `cell.graph()` returns `nodes/edges/stats`
- `cell.inspect_artifact(...)` returns ABI metadata / dependencies (or `abi_metadata_present=false`)

2. Update -> Validating

```text
cell.swap(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.info(<dcell_id>)
```

Expected:
- `driver_cell.hot_swap_state = Validating`
- `driver_cell.validation_deadline_tick` is populated

3. Manual rollback during validation

```text
cell.rollback(<dcell_id>)
cell.info(<dcell_id>)
```

Expected:
- `driver_cell.hot_swap_state = Idle`
- `driver_cell.validation_deadline_tick = nil`
- `driver_cell.loader_cell_id` returns to previous value

4. Manual commit during validation

```text
cell.swap(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.commit(<dcell_id>)
cell.info(<dcell_id>)
```

Expected:
- `driver_cell.hot_swap_state = Idle`
- `driver_cell.validation_deadline_tick = nil`

5. Auto-commit after grace window (default ~60s)

```text
cell.swap(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.info(<dcell_id>)
sys.time()
```

Wait until the deadline passes, then run:

```text
cell.info(<dcell_id>)
```

Expected:
- `driver_cell.hot_swap_state = Idle`
- `driver_cell.validation_deadline_tick = nil`
- no new health failure recorded

6. Auto-rollback via injected panic (requires `qemu-test-export`)

```text
cell.swap(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.debug_fault(<dcell_id>, "panic")
cell.info(<dcell_id>)
```

Expected:
- rollback path runs during validation
- `driver_cell.hot_swap_state = Idle`
- `driver_cell.stats.restart_count` does not increase for this case

7. Idle panic -> restart -> unload integrity

```text
cell.debug_fault(<dcell_id>, "panic")
cell.info(<dcell_id>)
cell.unload(<dcell_id>)
```

Expected:
- `driver_cell.stats.restart_count` increases
- cell returns to `Running`
- unload succeeds (loader registry remains consistent)

## Notes

- `cell.update(...)` is kept as a compatibility alias for `cell.swap(...)` in this phase.
- Legacy `cell <method> ...` command syntax was removed; use `cell.xxx(...)`.
