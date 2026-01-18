# Legacy POSIX Implementation Removal & Migration Plan

This document outlines the strategy for removing legacy POSIX-compatible implementations (`Process`, `Signal`, `ProcFS`) that conflict with the ExoRust (SAS/SPL/Async-First) architecture.

## 1. Objective

To transition the kernel codebase from a traditional POSIX-like process model to the ExoRust Domain/Cell/Task model, eliminating unnecessary overhead and complexity associated with legacy support.

## 2. Strategy: "Isolate, Substitute, Delete"

We will adopt a strategy that prioritizes isolation into a compatibility layer to prevent `cfg` scattering.

### Phase 0: Visualization & Baseline (Immediate Action)
*   **Action:** Search and document all usages of `ProcessId`, `procfs`, `signal`, `fork`, `exec`.
*   **Outcome:** `docs/legacy_usage_baseline.md`. Use this to design the "Narrow Traits" between Core and Compat.

### Phase 1: Isolation & Dependency Inversion
**Goal:** Isolate legacy definitions into `compat` module with **one-way dependency** (Compat depends on Core).

1.  **Dependency Direction:**
    *   **Core:** Defines traits (e.g., `ProcessLike`, `ProcView`) and logic (Executor, MM). Does **not** know about `ProcessId` or `Signal` structs.
    *   **Compat:** Implements Core traits using legacy logic.
2.  **Single Gating Point:**
    *   `kernel/src/compat/mod.rs` is the **only** place with `#[cfg(feature = "posix-compat")]`.
    *   Internal files in `compat/` do not use `cfg`. Linker includes/excludes them based on the module gate.
3.  **Move & Re-export:**
    *   Move `process.rs`, `signal.rs`, `procfs` (process parts) to `kernel/src/compat/posix/`.

### Phase 2: Shim Restrictions & Observation Schema
**Goal:** Establish `DomainId` as truth and `sys/cells` as observation.

1.  **Hardened Shim:**
    *   `ProcessId` -> `pub(crate)` inside `compat`.
    *   Conversion: One-way `From<ProcessId> for DomainId`.
    *   **Safety:** CI check to ban `ProcessId` usage outside `compat`.
2.  **ProcFS Split & New Schema:**
    *   `procfs::process` -> `compat/posix`.
    *   `sys/cells` Schema Definition:
        *   `sys/cells/<id>/info` (id, name, state, quota)
        *   `sys/cells/<id>/tasks` (list of tasks)
        *   `sys/cells/<id>/mem` (rss, mapped, faults)
    *   This schema must work even when `posix-compat` is OFF.

### Phase 3: Signal & AddressSpace Redefinition
**Goal:** Replace internal logic with ExoRust primitives.

1.  **Signals -> Events:**
    *   Requirements Breakdown:
        *   **TaskCancel** (Future cancellation)
        *   **DomainStop** (Management)
        *   **FaultNotify** (Error propagation)
    *   Replace `signal.rs` logic with these specific mechanisms.
2.  **AddressSpace Split:**
    *   `GlobalMappings` (SAS Core)
    *   `ProtectionView` (Security: MPK/Guard)
    *   `LegacyProcessAddressSpace` (Compat: CR3/ASID)

### Phase 4: Deprecation & Cleanup
**Goal:** Disable legacy support.

1.  **Default OFF:** Switch `posix-compat` to disabled.
2.  **Acceptance:**
    *   Build passes.
    *   `sys/cells` observes system state.
    *   Cancel/Stop works.
3.  **Removal:** Delete `kernel/src/compat/posix/`.

## 4. Acceptance Criteria

*   [ ] Kernel builds with `default-features = false`.
*   [ ] `ProcessId` usage is physically impossible or strictly banned outside `compat`.
*   [ ] `compat` module depends on Core traits; Core does not depend on Compat types.
*   [ ] `sys/cells` provides observability without `procfs`.
*   [ ] Task cancellation and Domain stopping work without standard signals.
*   [ ] Memory protection (MPK, Guard pages) functions without Process Address Space logic.
