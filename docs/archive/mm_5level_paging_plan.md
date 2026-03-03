# mm 5-Level Paging Implementation Plan

## Goal
Implement 5-level paging (LA57) across mm while preserving 4-level fallback. The kernel should boot on CPUs with and without LA57 support, and use a consistent paging mode across BSP/APs.

## Scope
- Bootloader page table creation and handoff
- Kernel paging mode detection and configuration
- Core address helpers (canonicalization, indices)
- Page table walker/manager updates (map/unmap/translate)
- RCU and manual page-walk users
- Cross-module address usage auditing (x86_64::VirtAddr vs mm::VirtAddr)
- Validation and documentation

## Non-Goals (Initial)
- 512GB huge pages via PML4 PS bit (treat as unsupported unless needed)
- Expanding kernel virtual layout beyond current higher-half ranges unless required
- IOMMU paging changes (remains 4-level per VT-d spec)

## Assumptions / Decisions to Lock Early
- Paging mode selection: runtime (auto/force/disable) with 4-level fallback.
- Canonicalization depends on mode:
  - 4-level: sign-extend bit 47 (48-bit canonical)
  - 5-level: sign-extend bit 56 (57-bit canonical)
- Kernel will continue using current higher-half base unless a larger VA layout is explicitly requested.
- LA57 detection uses CPUID.(EAX=07H, ECX=0):ECX[16].

## Phase 0: Baseline Review and Design
- Inventory all PML4 assumptions and 4-level index calculations.
- Decide on runtime vs compile-time mode (recommend runtime with boot flag).
- Define a single source of truth for paging mode (global config in mm).
- Define boot protocol extension to communicate root table level and mode.

## Phase 1: Bootloader Changes
- Detect LA57 support and select mode based on policy.
- Add PML5 support:
  - Option A: Build full 5-level maps via UefiMapper
  - Option B: Wrap existing PML4 with a single PML5 entry (minimal change)
- Set CR4.LA57 before enabling 5-level root and reload CR3 with PML5.
- Extend `ExoBootInfo` with fields like:
  - `paging_levels` (4 or 5)
  - `la57_enabled` (bool)
  - `page_table_base` remains root physical address
- Bump boot protocol version if ABI changes are not backward-compatible.

## Phase 2: Kernel Paging Mode Init
- Read new boot fields; initialize a global `PagingMode`.
- Ensure BSP respects bootloader mode; avoid reconfiguring unless explicitly requested.
- Update AP bring-up to set CR4.LA57 consistently and load the correct CR3 root.
- Add a safe check to refuse 5-level if CPU lacks LA57.

## Phase 3: Core Address Helpers
- Introduce `PagingMode` enum and `PagingConfig` in mm.
- Add canonicalization helpers:
  - `canonicalize(addr, mode)`
  - `VirtAddr::new_4level` and `VirtAddr::new_5level`
  - Keep `VirtAddr::new` as a thin wrapper over the active mode where possible.
- Replace `page_table_indices()` with mode-aware indices:
  - Return `[usize; 5]` plus `levels`
  - Provide helpers to fetch indices by level
- Update constants and boundary checks that assume 48-bit canonical space.

## Phase 4: Page Table Walkers and Manager
- Update `PageTableWalker` to walk 4 or 5 levels based on mode.
- Update `PageTableManager`:
  - Map/unmap/translate iterate through levels
  - Create missing intermediate tables (including PML5->PML4 when needed)
- Explicitly handle huge page behavior:
  - Allow 1GiB/2MiB as today
  - Reject PML4 PS if not supporting 512GB pages
- Ensure TLB invalidation paths still work (no change expected).

## Phase 5: RCU and Manual Walkers
- Update `rcu_vma`:
  - 5-level index computation
  - `pte_values` size to 5 (or max size + `levels` field)
- Replace manual 4-level walks in:
  - `address_space` NUMA hint path
  - THP promotion
  - Any other direct PML4/PDPT/PD/PT traversal
  - Prefer shared walker helper to prevent drift

## Phase 6: Cross-Module Address Audit
- Audit usages of `x86_64::VirtAddr` (48-bit canonical) in mm paths.
- For kernel-space VA use `crate::mm::higher_half::VirtAddr` where possible.
- For DMA/IOMMU or external paths, ensure addresses remain < 48-bit if still using `x86_64::VirtAddr` or add explicit checks/conversions.
- Update debug strings ("PML4") to be mode-aware.

## Phase 7: Validation
- Unit tests:
  - Canonicalization for both modes
  - Index calculation for 4/5 levels
  - Walker translation for 4k/2m/1g pages
- Boot tests:
  - LA57 supported CPU: boot in 5-level mode
  - LA57 unsupported CPU: fallback to 4-level mode
- SMP test: ensure APs run with the same paging mode.

## Phase 8: Documentation and Rollout
- Update `README.md` / `IMPLEMENTATION_STATUS.md` with LA57 support status.
- Add a boot flag (e.g. `mm.la57=auto|force|disable`).
- Document known limitations (no 512GB huge pages, address space layout unchanged).

## Risks and Mitigations
- Risk: `x86_64` crate rejects 57-bit addresses.
  - Mitigation: keep kernel VA layout within 48-bit or migrate to custom `VirtAddr`.
- Risk: inconsistent CR4.LA57 across CPUs.
  - Mitigation: enforce mode during BSP/AP init and assert in debug builds.
- Risk: boot protocol mismatch between bootloader and kernel.
  - Mitigation: bump version and guard on mismatch at boot.

## Detailed Task Breakdown (Actionable)
### Bootloader and Boot Protocol
- Extend `libs/boot_proto/src/lib.rs`:
  - Add `paging_levels: u8` and `la57_enabled: u8` (or `bool` if ABI-safe).
  - Bump `ExoBootInfo.version` if structure layout changes.
- Update `bootloader/src/page_table.rs`:
  - Add PML5 support (minimal wrapper or full 5-level builder).
  - Add helper to allocate root at level 5 and attach existing PML4.
- Update `bootloader/src/main.rs`:
  - Detect LA57 capability via CPUID.
  - Add boot policy (`auto|force|disable`), pick mode.
  - If 5-level: set CR4.LA57 and load CR3 with PML5 root.
  - Populate boot info fields for paging mode.

### Kernel Paging Mode and CR4.LA57
- Add `PagingMode` enum and global config in `kernel/src/mm/higher_half.rs` (or `kernel/src/mm/mod.rs`):
  - `levels()` returns 4 or 5.
  - `canonicalize(addr)` depends on active mode.
  - Store from boot info during early init.
- Wire boot info consumption to mm init (search where `ExoBootInfo` is used).
- Ensure AP init enables LA57 consistently (AP bring-up code path).

### Address Helpers and Indices
- Update `kernel/src/mm/higher_half.rs`:
  - `VirtAddr::new` uses mode-aware canonicalization.
  - `page_table_indices()` returns 5 indices (plus mode) or a struct.
  - Update constants/comments that assume 48-bit canonical.

### Page Table Walker and Manager
- Update `PageTableWalker` in `kernel/src/mm/higher_half.rs`:
  - Walk PML5->PML4->PDPT->PD->PT when mode=5.
  - Keep 4-level path for fallback.
- Update `PageTableManager` mapping paths:
  - `map_page`, `map_2mb_page`, `map_1gb_page`, `unmap_page`, `translate`.
  - Add new helper to ensure intermediate tables across 5 levels.
- Keep huge page behavior unchanged (1GiB/2MiB only).

### RCU and Manual Walkers
- Update `kernel/src/mm/rcu_vma.rs`:
  - Extend `PageWalkResult.pte_values` to 5 or add `levels` + vector.
  - 5-level index computation.
- Replace manual 4-level walks in:
  - `kernel/src/mm/address_space.rs` (NUMA hint path).
  - `kernel/src/mm/address_space.rs` (THP promotion).
  - Any other direct PT walk.
  - Use shared helper or `PageTableWalker`.

### Cross-Module Address Audit
- Audit `x86_64::VirtAddr` usage under `kernel/src/mm` and related paths.
- Convert kernel paging paths to `crate::mm::higher_half::VirtAddr`.
- Where `x86_64::VirtAddr` remains, ensure address < 48-bit or add guard.

### Tests and Validation
- Add unit tests for:
  - Canonicalization for 4/5 levels.
  - Index calculation for both modes.
  - Walker translation for 4k/2m/1g pages in both modes.
- Boot test matrix:
  - LA57 CPU, auto mode -> 5-level.
  - LA57 CPU, disable -> 4-level.
  - Non-LA57 CPU, auto -> 4-level.
- SMP sanity check: BSP/AP same paging mode.

## File Touch Map (Likely)
- `bootloader/src/main.rs`
- `bootloader/src/page_table.rs`
- `libs/boot_proto/src/lib.rs`
- `kernel/src/mm/higher_half.rs`
- `kernel/src/mm/address_space.rs`
- `kernel/src/mm/rcu_vma.rs`
- `kernel/src/mm/mod.rs` (export mode/config)
- `kernel/src/kernel_content.rs` or early init (boot info consumption)
- `kernel/src/interrupts/exceptions.rs` (debug text)

## Open Questions
- Should kernel keep current higher-half base or expand to leverage 57-bit VA?
- Should PML5 be fully populated or wrap existing PML4 with single entry?
- How to expose boot policy (kernel cmdline vs compile-time)?

## Recommended Defaults (If No Preference)
- Mode policy: `auto` (use LA57 if supported, else 4-level).
- PML5 build: wrapper root; map PML4 into PML5 entry 0 and 511 to preserve user+kernel halves.
- Keep current virtual layout within 48-bit canonical space for initial support.
- Boot protocol fields as `u64` for ABI alignment (`paging_levels`, `la57_enabled`).

## Boot Protocol Spec (Finalized)
- `ExoBootInfo.version = 2` (new fields appended; ABI change).
- `ExoBootInfo.page_table_base`: root page table physical address (PML4 or PML5).
- `ExoBootInfo.paging_levels`: `4` or `5`.
- `ExoBootInfo.la57_enabled`: `1` if CR4.LA57 is set, else `0`.
- Compatibility rule:
  - If `version < 2`, kernel treats paging as 4-level and `la57_enabled = 0`.
  - If `version > EXO_BOOT_INFO_VERSION`, kernel warns and falls back to safe defaults.

## Suggested Implementation Order
1. Boot protocol extension + kernel parsing (no behavior change yet).
2. Bootloader LA57 detection + PML5 wrapper + CR4.LA57 enable.
3. Mode-aware `VirtAddr` canonicalization + indices + walkers/manager.
4. RCU/manual walkers + NUMA/THP paths.
5. Tests + documentation.

## Definition of Done (MVP)
- Non-LA57 CPU boots with 4-level paging.
- LA57 CPU boots with 5-level paging using the same VA layout.
- Page walks, map/unmap, and fault handling work in both modes.
- Debug output reflects PML4/PML5 accurately.
