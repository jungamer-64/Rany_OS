# rustc ICE Reproduction Case

## Bug

This reproduces an Internal Compiler Error (ICE) in rustc related to the `annotate_snippets` error rendering library.

**Related Issues:**

- <https://github.com/rust-lang/rust/issues/146398> (slice index starts at 5 but ends at 4)
- <https://github.com/rust-lang/rust/issues/148643> (Patch span is beyond the end of buffer)

## Error Message

```
thread 'rustc' panicked at library/alloc/src/vec/mod.rs:2849:36:
slice index starts at 36 but ends at 35
```

## Stack Trace

```
<annotate_snippets::renderer::styled_buffer::StyledBuffer>::replace
annotate_snippets::renderer::render::render
<rustc_errors::annotate_snippet_emitter_writer::AnnotateSnippetEmitter>::emit_messages_default
<rustc_resolve::Resolver>::resolve_crate
```

## Root Cause

When a macro defined in one file is invoked in another file, and the macro expansion contains an undefined type/module, the compiler tries to render an error diagnostic that spans both files. The `annotate_snippets` library incorrectly calculates byte ranges for the error underlines, resulting in an invalid slice range (start > end).

This is a regression introduced when `annotate_snippets` became the default error renderer on nightly (PR #148188).

## Affected Versions

- rustc 1.89.0+ (stable, confirmed on Linux)
- rustc 1.93.0-nightly
- rustc 1.94.0-nightly (24139cf84 2025-12-20) - confirmed

## Platform

The ICE was observed on:

- **Platform:** x86_64-unknown-linux-gnu

Note: The ICE may not reproduce on Windows due to different line ending handling (CRLF vs LF).

## To Reproduce

```bash
# On Linux with nightly rustc:
cargo build
```

## Workaround

If you encounter this ICE in your project:

1. **Fix the actual error** - The underlying issue is a genuine compilation error (undefined type/module). Use an older stable rustc to see the actual error message:

   ```bash
   rustup run stable cargo build
   ```

2. **Use older nightly** - Switch to a nightly version before the annotate-snippets change:

   ```bash
   rustup install nightly-2025-08-01
   rustup run nightly-2025-08-01 cargo build
   ```

3. **Disable the new error renderer** (if the option exists):

   ```bash
   RUSTC_FLAGS="-Z no-annotate-snippets" cargo build
   ```

## Files

- `src/macros.rs` - Defines a macro that references an undefined module
- `src/main.rs` - Invokes the macro, causing multi-file diagnostic
