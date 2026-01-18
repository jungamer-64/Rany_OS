# Legacy Usage Baseline Report (Phase 0)

This document establishes the baseline usage of legacy POSIX features (`ProcessId`, `Signal`, `ProcFS`) in the Rany_OS kernel as of January 2026.

## 1. ProcessId Usage

**Definition:** `kernel/src/task/process.rs`

### Critical Dependencies (Must be refactored)
*   **`kernel/src/service_impl.rs`**: **HIGH RISK**. Mimics detailed process contexts for NVMe and FS operations.
    *   Creates fake processes (`caller_nvme`, `target_nvme`) to satisfy `Context` checks.
    *   `list_processes` (ps) iterates 0..100 PIDs.
    *   *Migration:* Must replace with `DomainId` and new `sys/cells` iteration.
*   **`kernel/src/task/context.rs`**: Likely holds Owner ID context.

### Replacements Available
*   `kernel/src/domain_system.rs`: `DomainId`, `Domain` structure.
*   `kernel/src/security/capability.rs`: `DomainCapabilities`, `GrantToken`.
    *   *Strategy:* `service_impl` should use `DomainId` and `DomainCapabilities` directly.

## 2. Signal Usage

**Definition:** `kernel/src/task/signal.rs`

### Critical Dependencies
*   **`kernel/src/unwind/mod.rs`**: **LOW RISK**.
    *   Uses `is_signal_frame` bool in `AugmentationData`.
    *   *Finding:* Does **not** import `Signal` types. It parsing standard DWARF `S` flag. Safe to keep as "Async Frame" concept.
*   **`kernel/src/task/mod.rs`**: Re-exports `Signal` types.

### Replacements Available
*   `kernel/src/ipc/pipe.rs`: `ZeroCopyChannel` for event notification.
*   `kernel/src/domain_system.rs`: `DomainState` (Active/Suspended) handles Stop/Resume signals.
    *   *Strategy:* Stop/Cont -> `Domain::suspend()`, `Domain::resume()`.
    *   *Strategy:* Kill -> `Domain::terminate()`.

## 3. File System & IO

**Definition:** `kernel/src/fs/mod.rs`

### Dependencies
*   **`kernel/src/fs/fs_abstraction.rs`**: **CLEAN**.
    *   `FileHandle` is an object (`struct`), not an `int`.
    *   FS layer is **decoupled** from Process FD tables.
    *   FD tables are likely implemented only within `process.rs` or `service_impl.rs`.

## 4. Migration Strategy Implications

1.  **Compat Module:** `process.rs` and `signal.rs` can be moved to `compat` with minimal friction for Core (Executor/MM/FS).
2.  **Shim Priority:** `service_impl.rs` is the primary "customer" of the legacy layer. It will need the shim immediately.
3.  **Unwind:** No action needed for Phase 1.
