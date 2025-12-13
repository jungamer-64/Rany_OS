Title: Cannot run kernel/security crate tests locally due to duplicate lang item (E0152)

Description:
When running `cargo test` for kernel or the extracted `libs/security` crate, the build fails with error E0152 complaining about duplicate lang items (e.g. `sized` in `core` or `exchange_malloc` in `alloc`). The compiler reports that the lang item is defined both in the rustup sysroot (`...\libcore-*.rlib`) and in a locally built copy (`target/.../libcore-*.rlib`).

Steps to reproduce:
1. From repo root: `cargo test --lib --manifest-path kernel/Cargo.toml -vv -j1`
2. Observe E0152 duplicate lang item errors near the end of the build.

Notes & logs:
See `docs/E0152_INVESTIGATION.md` for full details and snippets of the failing build log.

Workarounds tried:
- `cargo clean`
- `cargo test -Z build-std=core,alloc,compiler_builtins` (still resulted in duplicate errors / other errors)
- Isolating builds into different target directories (didn't resolve duplication)
- Creating a host-only harness `tools/cap_harness` for capability tests (works; we use this for now)

Desired outcome:
- Be able to run `cargo test --lib --manifest-path kernel/Cargo.toml` locally on a developer machine without encountering E0152, or
- Have a documented, reproducible workaround or CI strategy that verifies the same logic (e.g., run `tools/cap_harness` in CI for capabilities while investigating cargo issue).

Assignee: TBD
Labels: build, workspace, tests

If someone from the Rust/Cargo team can point to a recommended remediation or we should open an upstream issue, we can prepare a minimal reproduction case and open one upstream.
