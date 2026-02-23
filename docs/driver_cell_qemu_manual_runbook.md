# DriverCell / LiveUpdate Manual QEMU Runbook

This runbook validates DriverCell-first `cell.*` commands and LiveUpdate behavior
on QEMU using the `driver_cell_probe` fixture cells.

## Prerequisites

- Nightly toolchain from `rust-toolchain.toml` (includes `rust-src`)
- `x86_64-exorust-cell.json` (repo-local cell target spec for `cdylib` fixtures)
- Build kernel with `qemu-test-export` when using `cell.debug_fault(...)`

## Build Fixtures

```bash
scripts/build_driver_cell_probe_fixtures.sh --profile debug
```

Generated artifacts:

- `target/initramfs.tar` (contains `drivers/driver_cell_probe.cell` = v1)
- `target/x86_64-exorust/debug/cells/driver_cell_probe_v1.cell`
- `target/x86_64-exorust/debug/cells/driver_cell_probe_v2.cell`

## Launch QEMU (interactive ExoShell)

```bash
./scripts/run.sh --serial stdio --monitor --tcg
```

Confirm startup logs mention:

- `Included initramfs.tar`
- `Deployed ... Cell(s) to /cells`
- `Loaded driver cell 'driver_cell_probe' as dcell=...`

## ExoShell Checks

1. Preflight

```text
fs.entries("/cells")
cell.list()
cell.stats(<dcell_id>)
```

Expected:
- `driver_cell_probe` exists
- `State: Running`
- `HotSwap State: Idle`
- `Loader Cell ID` and `Domain ID` are populated

2. Update -> Validating

```text
cell.update(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.health(<dcell_id>)
```

Expected:
- `HotSwap State: Validating`
- `Validation Deadline Tick` is not `-`

3. Manual rollback during validation

```text
cell.rollback(<dcell_id>)
cell.health(<dcell_id>)
cell.stats(<dcell_id>)
```

Expected:
- `HotSwap State: Idle`
- `Validation Deadline Tick: -`
- `Loader Cell ID` returns to previous value

4. Manual commit during validation

```text
cell.update(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.commit(<dcell_id>)
cell.health(<dcell_id>)
```

Expected:
- `HotSwap State: Idle`
- `Validation Deadline Tick: -`

5. Auto-commit after grace window (default ~60s)

```text
cell.update(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.health(<dcell_id>)
sys.time()
```

Wait until the deadline passes, then run:

```text
cell.health(<dcell_id>)
cell.stats(<dcell_id>)
```

Expected:
- `HotSwap State: Idle`
- `Validation Deadline Tick: -`
- no new health failure recorded

6. Auto-rollback via injected panic (requires `qemu-test-export`)

```text
cell.update(<dcell_id>, "/cells/driver_cell_probe_v2.cell")
cell.debug_fault(<dcell_id>, "panic")
cell.health(<dcell_id>)
cell.stats(<dcell_id>)
```

Expected:
- rollback path runs during validation
- `HotSwap State: Idle`
- `restart_count` does not increase for this case

7. Idle panic -> restart -> unload integrity

```text
cell.debug_fault(<dcell_id>, "panic")
cell.stats(<dcell_id>)
cell.unload(<dcell_id>)
```

Expected:
- `restart_count` increases
- cell returns to `Running`
- unload succeeds (loader registry remains consistent)
