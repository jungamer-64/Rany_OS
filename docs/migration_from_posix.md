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
**Goal:** Establish `DomainId` as truth and `/sys/cell` as observation.

1.  **Hardened Shim:**
    *   `ProcessId` -> `pub(crate)` inside `compat`.
    *   Conversion: One-way `From<ProcessId> for DomainId`.
    *   **Safety:** CI check to ban `ProcessId` usage outside `compat`.
2.  **ProcFS Split & New Schema:**
    *   `procfs::pid` -> `compat/posix`.
    *   `/sys/cell` Schema Definition (core, read-only):
        *   `name`, `state`, `tasks`, `task_ids`
        *   `memory_kb`, `memory_bytes`, `rrefs`
        *   `runtime_ticks`, `context_switches`, `created_at`
        *   `numa_node`, `dependencies`, `dependents`
        *   `panic_message`, `last_error`
    *   This schema must work even when `posix-compat` is OFF.

    *   `/proc/<pid>` replacement scope (initial):

        | Legacy path | Core replacement | Notes |
        |---|---|---|
        | `/proc/<pid>/status` | `/sys/cell/<id>/{name,state,tasks,task_ids,memory_kb,rrefs,last_error,panic_message}` | Multi-field read via sysfs |
        | `/proc/<pid>/stat` | `/sys/cell/<id>/{runtime_ticks,context_switches,created_at}` | Timing counters |
        | `/proc/<pid>/cmdline` | none (compat only) | Keep in compat until a Domain-aware equivalent exists |
        | `/proc/<pid>/maps` | none (compat only) | Depends on per-process address space |
        | `/proc/<pid>/fd` | none (compat only) | Depends on per-process FD table |
        | `/proc/<pid>/exe` | none (compat only) | Process semantic |
        | `/proc/<pid>/mem` | none (compat only) | Process semantic |

    *   `/sys/system` Schema Definition (core, read-only):
        *   `version`, `uptime`, `meminfo`, `cpuinfo`, `stat`, `loadavg`
        *   `filesystems`, `mounts`, `cmdline`
        *   `kernel/hostname`, `kernel/ostype`, `kernel/version`
        *   `net/dev`, `net/tcp`, `net/udp`, `net/arp`
    *   `posix-compat` ON: `/proc` の system/net 系は `/sys/system` への read-only facade として実装し、出力のズレを防ぐ。
    *   Global `/proc` replacement scope (initial):

        | Legacy path | Core replacement | Notes |
        |---|---|---|
        | `/proc/version` | `/sys/system/version` | Keep text format for compat |
        | `/proc/uptime` | `/sys/system/uptime` | Same units/format |
        | `/proc/meminfo` | `/sys/system/meminfo` | Same keys as legacy |
        | `/proc/cpuinfo` | `/sys/system/cpuinfo` | Same layout as legacy |
        | `/proc/stat` | `/sys/system/stat` | Same layout as legacy |
        | `/proc/loadavg` | `/sys/system/loadavg` | Same layout as legacy |
        | `/proc/filesystems` | `/sys/system/filesystems` | Same layout as legacy |
        | `/proc/mounts` | `/sys/system/mounts` | Same layout as legacy |
        | `/proc/cmdline` | `/sys/system/cmdline` | Same layout as legacy |
        | `/proc/sys/kernel/hostname` | `/sys/system/kernel/hostname` | Core is read-only; compat may allow writes |
        | `/proc/sys/kernel/ostype` | `/sys/system/kernel/ostype` | Read-only |
        | `/proc/sys/kernel/version` | `/sys/system/kernel/version` | Read-only |
        | `/proc/net/dev` | `/sys/system/net/dev` | Same layout as legacy |
        | `/proc/net/tcp` | `/sys/system/net/tcp` | Same layout as legacy |
        | `/proc/net/udp` | `/sys/system/net/udp` | Same layout as legacy |
        | `/proc/net/arp` | `/sys/system/net/arp` | Same layout as legacy |

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
    *   Migration steps (shim-first):
        *   Introduce `AddressSpaceOps` for core MM paths (map/unmap/protect/scan).
        *   Move `fork()` / `exec_reset()` into `LegacyProcessAddressSpace` under compat.
        *   Wire `task::process` to call compat address-space ops only when `posix-compat` is ON.
        *   Replace ProcessId-driven MM callsites with DomainId/TaskContext handles.

### Phase 4: Deprecation & Cleanup
**Goal:** Disable legacy support.

1.  **Default OFF:** Switch `posix-compat` to disabled.
2.  **Acceptance:**
    *   Build passes.
    *   `/sys/cell` observes system state.
    *   Cancel/Stop works.
3.  **Removal:** Delete `kernel/src/compat/posix/`.

## 4. Acceptance Criteria

*   [ ] Kernel builds with `default-features = false`.
*   [ ] `ProcessId` usage is physically impossible or strictly banned outside `compat`.
*   [ ] `compat` module depends on Core traits; Core does not depend on Compat types.
*   [ ] `/sys/cell` provides observability without `procfs`.
*   [ ] Task cancellation and Domain stopping work without standard signals.
*   [ ] Memory protection (MPK, Guard pages) functions without Process Address Space logic.
