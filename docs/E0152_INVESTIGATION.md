# Investigation: duplicate lang item (E0152) when running tests

Summary
-------
While enabling and running kernel-level unit tests locally (e.g., `cargo test --lib --manifest-path kernel/Cargo.toml`), the build frequently fails with error E0152 (duplicate lang item) for `core`/`alloc` (e.g. `sized`, `exchange_malloc`). The compiler reports two different definitions of the same lang item: one from the sysroot (rustup toolchain) and one from a locally built copy in `target/.../deps/libcore-*.rlib` or `liballoc-*.rlib`.

Reproduction
------------
1. Clean the kernel target: `cargo clean --manifest-path kernel/Cargo.toml`
2. Run (from workspace root):
   - `cargo test --lib --manifest-path kernel/Cargo.toml -vv -j1`
3. The build compiles many crates and then fails with E0152, e.g.:

   error[E0152]: duplicate lang item in crate `alloc` (which `rany_os` depends on): `exchange_malloc`
   note: the lang item is first defined in crate `alloc` (which `std` depends on)
   note: first definition in `alloc` loaded from C:\Users\...\liballoc-*.rlib (sysroot)
   note: second definition in `alloc` loaded from D:\Rust\Rany_OS\target\...\liballoc-*.rlib

Observations
------------
- The local `target/.../deps` contains `libcore-*.rlib` and `liballoc-*.rlib` produced during the build. This indicates the build process compiled the standard library components from source for the workspace target.
- The duplication occurs even when invoking `cargo test -p libs/security` or `cargo test -p rany_kernel` directly; the security crate tests (ported from kernel) fail due to E0152 as well.
- A small host-only harness (tools/cap_harness) containing a minimal, self-contained implementation of the grant logic was used for fast verification; those tests passed reliably on the host. We reverted a change to make that harness depend on `libs/security` because `libs/security` compilation itself is blocked by the E0152 problem.

Likely causes
-------------
This class of error is commonly caused by mixing sysroot-provided standard library crates (core/alloc) with locally-built copies (e.g., via `-Z build-std` or when `compiler_builtins`/`rustc-dep-of-std` gets built in-tree). Some relevant issues in the Rust/Cargo repos suggest this is a subtle workspace/build interaction:
- Duplicate lang items when using `-Z build-std`
- Cargo sometimes links `libcore` twice when different profiles or build strategies are involved

Short-term mitigations
----------------------
- Keep `tools/cap_harness` as the host-only verification harness (it is independent and tests pass) and add/extend tests there for capability logic (`cap.grant`). This gives quick feedback and is suitable for CI.
- Avoid making `libs/security` a dependency of `tools/cap_harness` until the E0152 issue is resolved; keep the harness self-contained for now.

Long-term actions / proposals
----------------------------
1. Decide on a consistent strategy for running host unit tests in this repository. Options:
   - Use host-only harnesses (tools/*) for logic that should be tested on the host. Add CI jobs to run them.
   - Move testable modules (e.g., the security code) into separate workspace crates (e.g., `libs/security`) + ensure we can compile and test them on host by fixing the workspace build issue.

2. Investigate why `libcore`/`liballoc` are being built locally for the workspace when running `cargo test`:
   - Search for any `build-std` configuration in workspace `.cargo/config.toml` files or user-level cargo config (`%USERPROFILE%/.cargo/config.toml`). (No per-user config found in this environment.)
   - Reproduce with `-Z build-std=core,alloc,compiler_builtins` and study differences: sometimes using build-std introduces duplicates (we observed duplicate errors even with `-Z build-std`).
   - Consider isolating builds for crates that cause local std builds and split them into separate invocations to avoid mixing sysroot-provided and locally built standard library artifacts.

3. If this is a Cargo/Rust bug, file or link an issue in rust-lang/cargo or rust-lang/rust with a minimal reproduction (we can extract a small repro from this workspace). Include the `-Z` flags and logs.

What we changed in this branch
------------------------------
- Added `libs/security` crate with the capability manager and tests (tests exist but running them is blocked by the duplicate lang item problem).
- Kept `tools/cap_harness` as the host-only testing harness (independent and passing).

Next steps I can take (pick one or more):
- Try to reproduce the duplicate-lang-item issue with a minimal sample project and file a bug upstream (I can prepare a minimal repro and open an issue).
- Attempt a workspace-level `.cargo/config.toml` change to use consistent `build-std` or isolate standard library building, and test whether that resolves the duplication (risky; may require many rebuilds).
- Keep the current host-only tests and move forward with more test coverage in `tools/*` while the cargo issue is investigated.

If you'd like, I can take the next step of creating a minimal repro and opening an issue with the Rust/Cargo teams, or I can try the workspace `build-std` change and test the outcome locally.
