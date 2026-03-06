use super::*;
use crate::sync::poison_lock::PoisonLock;
use alloc::vec::Vec;

// Required for inline assembly macros and atomic ordering constants
use core::arch::asm;
use core::sync::atomic::Ordering;

#[inline]
fn is_valid_hot_gs_base(gs_base: u64) -> bool {
    if gs_base == 0 {
        return false;
    }

    let addr = gs_base as usize;
    let hot_start = core::ptr::addr_of!(PER_CPU_HOT) as usize;
    let hot_size = core::mem::size_of::<[PerCpuHot; MAX_CPUS]>();
    let hot_end = hot_start.saturating_add(hot_size);
    let hot_stride = core::mem::size_of::<PerCpuHot>();

    if hot_stride == 0 {
        return false;
    }
    if addr < hot_start || addr >= hot_end {
        return false;
    }
    if (addr - hot_start) % hot_stride != 0 {
        return false;
    }
    true
}

/// 静的に確保されたPer-CPUデータ配列 (Legacy - for backward compatibility)
/// 各CPUに対応するデータが格納される
pub(crate) static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData::new(0);
    [INIT; MAX_CPUS]
};

/// Per-CPUデータが初期化済みかどうか
pub(crate) static INITIALIZED: spin::Once<()> = spin::Once::new();

/// 初期化済みCPU数
pub(crate) static ACTIVE_CPUS: PoisonLock<usize> = PoisonLock::new(0);
/// Online CPU bitmask (bit N set => CPU N online)
pub(crate) static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(0);

/// Fastpath adoption flag: true = CPUID supports FSGSBASE and we adopt rdgsbase/wrgsbase
/// Note: This is a global adoption decision. Each CPU must still enable CR4.FSGSBASE before use.
pub(crate) static GSBASE_FASTPATH: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// BSPのGSBaseが設定済みかどうか
/// read_gsbase_any() が初期化前にMSRからゴミ値を読み取るのを防ぐ
pub(crate) static BSP_GSBASE_SET: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Check if FSGSBASE fastpath is adopted (CPUID supports it)
#[inline]
pub fn can_use_fsgsbase() -> bool {
    GSBASE_FASTPATH.load(Ordering::Relaxed)
}

/// Read GSBase using the appropriate method for this CPU
///
/// Uses rdgsbase if fastpath is adopted AND this CPU has CR4.FSGSBASE enabled,
/// otherwise falls back to MSR read. This prevents #UD on APs before their CR4 is set.
/// Returns 0 if BSP GSBase has not been initialized yet (prevents MSR garbage).
///
/// # Safety
/// Must be called in kernel mode
#[inline]
pub unsafe fn read_gsbase_any() -> u64 {
    // GS baseがまだ設定されていなければ0を返す（MSRのゴミ値を防ぐ）
    if !BSP_GSBASE_SET.load(Ordering::Acquire) {
        return 0;
    }
    if can_use_fsgsbase() && is_fsgsbase_enabled() {
        read_gs_base()
    } else {
        read_gs_base_msr()
    }
}

/// Write GSBase using the appropriate method for this CPU
///
/// Uses wrgsbase if fastpath is adopted AND this CPU has CR4.FSGSBASE enabled,
/// otherwise falls back to MSR write. This prevents #UD on APs before their CR4 is set.
///
/// # Safety
/// - Must be called in kernel mode
/// - Value must point to valid Per-CPU data
#[inline]
pub unsafe fn write_gsbase_any(value: u64) {
    if can_use_fsgsbase() && is_fsgsbase_enabled() {
        write_gs_base(value)
    } else {
        write_gs_base_msr(value)
    }
}

/// Get reference to Per-CPU data for a specific CPU ID
///
/// # Safety
/// Caller must ensure cpu_id is valid (< MAX_CPUS)
pub unsafe fn get_per_cpu_data(cpu_id: usize) -> &'static PerCpuData {
    &PER_CPU_DATA[cpu_id]
}

/// Get mutable reference to Per-CPU data for a specific CPU ID
///
/// # Safety
/// - Caller must ensure cpu_id is valid (< MAX_CPUS)
/// - Caller must ensure exclusive access (no concurrent mutable access)
pub unsafe fn get_per_cpu_data_mut(cpu_id: usize) -> &'static mut PerCpuData {
    &mut PER_CPU_DATA[cpu_id]
}

// ============================================================================
// Hot/Cold Per-CPU Accessors
// ============================================================================

/// Get reference to hot per-CPU data for a specific CPU ID
///
/// # Safety
/// Caller must ensure cpu_id is valid (< MAX_CPUS)
#[inline]
pub unsafe fn get_per_cpu_hot(cpu_id: usize) -> &'static PerCpuHot {
    &PER_CPU_HOT[cpu_id]
}

/// Get mutable reference to hot per-CPU data
///
/// # Safety
/// - cpu_id must be valid (< MAX_CPUS)
/// - Caller must ensure exclusive access
#[inline]
pub unsafe fn get_per_cpu_hot_mut(cpu_id: usize) -> &'static mut PerCpuHot {
    &mut PER_CPU_HOT[cpu_id]
}

/// Get reference to cold per-CPU data for a specific CPU ID
///
/// # Safety
/// Caller must ensure cpu_id is valid (< MAX_CPUS)
#[inline]
pub unsafe fn get_per_cpu_cold(cpu_id: usize) -> &'static PerCpuCold {
    &PER_CPU_COLD[cpu_id]
}

/// Get mutable reference to cold per-CPU data
///
/// # Safety
/// - cpu_id must be valid (< MAX_CPUS)
/// - Caller must ensure exclusive access
#[inline]
pub unsafe fn get_per_cpu_cold_mut(cpu_id: usize) -> &'static mut PerCpuCold {
    &mut PER_CPU_COLD[cpu_id]
}

/// Get the current CPU's hot data via GSBase
///
/// Returns None if GSBase is not initialized or validation fails
#[inline]
pub unsafe fn current_per_cpu_hot() -> Option<&'static PerCpuHot> {
    let gs_base = read_gsbase_any();
    if !is_valid_hot_gs_base(gs_base) {
        return None;
    }
    let hot = &*(gs_base as *const PerCpuHot);
    // Validate self_ptr to ensure GSBase points to valid PerCpuHot
    if hot.self_ptr != gs_base as usize {
        return None;
    }
    Some(hot)
}

/// Get the current CPU's hot data (mutable) via GSBase
///
/// # Safety
/// Caller must ensure exclusive access
#[inline]
pub unsafe fn current_per_cpu_hot_mut() -> Option<&'static mut PerCpuHot> {
    let gs_base = read_gsbase_any();
    if !is_valid_hot_gs_base(gs_base) {
        return None;
    }
    let hot = &mut *(gs_base as *mut PerCpuHot);
    // Validate self_ptr to ensure GSBase points to valid PerCpuHot
    if hot.self_ptr != gs_base as usize {
        return None;
    }
    Some(hot)
}

/// Check if a CPU is online
pub fn is_cpu_online(cpu_id: usize) -> bool {
    if cpu_id >= 64 {
        return false;
    }
    let mask = ONLINE_CPU_MASK.load(Ordering::Acquire);
    (mask & (1 << cpu_id)) != 0
}

/// GsBaseレジスタを読み取る
///
/// # Safety
/// GsBaseが有効なPer-CPUデータを指している必要がある
#[inline]
pub unsafe fn read_gs_base() -> u64 {
    let value: u64;
    // SAFETY: rdgsbaseはGsBaseレジスタの値を読み取る
    unsafe {
        asm!(
            "rdgsbase {0}",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// GsBaseレジスタに書き込む
///
/// # Safety
/// - 有効なPer-CPUデータへのポインタを渡す必要がある
/// - FSGSBASEが有効化されている必要がある（CR4.FSGSBASE）
#[inline]
pub unsafe fn write_gs_base(value: u64) {
    // SAFETY: wrgsbaseはGsBaseレジスタに値を書き込む
    unsafe {
        asm!(
            "wrgsbase {0}",
            in(reg) value,
            options(nostack, preserves_flags)
        );
    }
}

/// MSR経由でGsBaseを読み取る（FSGSBASEが無効な環境用）
///
/// # Safety
/// カーネルモードで実行される必要がある
#[inline]
pub unsafe fn read_gs_base_msr() -> u64 {
    const IA32_GS_BASE: u32 = 0xC000_0101;
    let low: u32;
    let high: u32;

    // SAFETY: MSR読み取りはカーネルモードで安全
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") IA32_GS_BASE,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }

    ((high as u64) << 32) | (low as u64)
}

/// MSR経由でGsBaseに書き込む（FSGSBASEが無効な環境用）
///
/// # Safety
/// - カーネルモードで実行される必要がある
/// - 有効なPer-CPUデータへのポインタを渡す必要がある
#[inline]
pub unsafe fn write_gs_base_msr(value: u64) {
    const IA32_GS_BASE: u32 = 0xC000_0101;
    let low = value as u32;
    let high = (value >> 32) as u32;

    // SAFETY: MSR書き込みはカーネルモードで安全
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_GS_BASE,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

// ============================================================================
// FS Base Functions (for Thread Local Storage)
// ============================================================================

/// FSBaseレジスタを読み取る
///
/// # Safety
/// FSBaseが有効なTLSデータを指している必要がある
#[inline]
pub unsafe fn read_fs_base() -> u64 {
    let value: u64;
    // SAFETY: rdfsbaseはFsBaseレジスタの値を読み取る
    unsafe {
        asm!(
            "rdfsbase {0}",
            out(reg) value,
            options(nostack, preserves_flags)
        );
    }
    value
}

/// FSBaseレジスタに書き込む
///
/// # Safety
/// - 有効なTLSデータへのポインタを渡す必要がある
/// - FSGSBASEが有効化されている必要がある（CR4.FSGSBASE）
#[inline]
pub unsafe fn write_fs_base(value: u64) {
    // SAFETY: wrfsbaseはFsBaseレジスタに値を書き込む
    unsafe {
        asm!(
            "wrfsbase {0}",
            in(reg) value,
            options(nostack, preserves_flags)
        );
    }
}

/// MSR経由でFSBaseを読み取る（FSGSBASEが無効な環境用）
///
/// # Safety
/// カーネルモードで実行される必要がある
#[inline]
pub unsafe fn read_fs_base_msr() -> u64 {
    const IA32_FS_BASE: u32 = 0xC000_0100;
    let low: u32;
    let high: u32;

    // SAFETY: MSR読み取りはカーネルモードで安全
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") IA32_FS_BASE,
            out("eax") low,
            out("edx") high,
            options(nostack, preserves_flags)
        );
    }

    ((high as u64) << 32) | (low as u64)
}

/// MSR経由でFSBaseに書き込む（FSGSBASEが無効な環境用）
///
/// # Safety
/// - カーネルモードで実行される必要がある
/// - 有効なTLSデータへのポインタを渡す必要がある
#[inline]
pub unsafe fn write_fs_base_msr(value: u64) {
    const IA32_FS_BASE: u32 = 0xC000_0100;
    let low = value as u32;
    let high = (value >> 32) as u32;

    // SAFETY: MSR書き込みはカーネルモードで安全
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") IA32_FS_BASE,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags)
        );
    }
}

/// CR4.FSGSBASEを有効化
///
/// # Safety
/// カーネルの初期化時に一度だけ呼ぶ必要がある
pub unsafe fn enable_fsgsbase() {
    const CR4_FSGSBASE: u64 = 1 << 16;

    let cr4: u64;
    // SAFETY: CR4の読み取り
    unsafe {
        asm!(
            "mov {0}, cr4",
            out(reg) cr4,
            options(nostack, preserves_flags)
        );
    }

    // FSGSBASEビットを設定
    let new_cr4 = cr4 | CR4_FSGSBASE;

    // SAFETY: CR4への書き込み
    unsafe {
        asm!(
            "mov cr4, {0}",
            in(reg) new_cr4,
            options(nostack, preserves_flags)
        );
    }
}

/// FSGSBASEが有効かどうかをチェック
pub fn is_fsgsbase_enabled() -> bool {
    const CR4_FSGSBASE: u64 = 1 << 16;

    let cr4: u64;
    unsafe {
        asm!(
            "mov {0}, cr4",
            out(reg) cr4,
            options(nostack, preserves_flags)
        );
    }

    (cr4 & CR4_FSGSBASE) != 0
}

/// CPUがFSGSBASE命令をサポートしているかチェック
///
/// CPUID.07H.0H:EBX[0] = 1 の場合サポート
///
/// # Safety
/// CPUID命令を実行する
pub unsafe fn check_fsgsbase_support() -> bool {
    // まず最大拡張機能番号を確認
    let max_leaf: u32;
    unsafe {
        // ebx/rbxはLLVMが使用するため、xchgで退避
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 0u32 => max_leaf,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }

    // リーフ7が利用可能かチェック
    if max_leaf < 7 {
        return false;
    }

    // CPUID.07H.0H でFSGSBASEサポートを確認
    let ebx_result: u32;
    unsafe {
        // rbxを退避してcpuid実行、結果をrdiに移動してrbxを復元
        asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx_result,
            inout("eax") 7u32 => _,
            inout("ecx") 0u32 => _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }

    // EBX bit 0 = FSGSBASE
    (ebx_result & 1) != 0
}

/// Per-CPUシステムを初期化
///
/// # Safety
/// - カーネル初期化時に一度だけ呼ばれる必要がある
/// - BSP（ブートストラッププロセッサ）から呼ぶ
///
/// # 初期化順序
/// 1. FSGSBASEを有効化（サポートされている場合）
/// 2. BSPのGsBaseを先に設定（current_cpu_id()が使えるように）
/// 3. 各CPUのデータを初期化
///
/// これにより、初期化中でも `current_cpu_id()` や `try_current_cpu_id()` を
/// 安全に呼び出すことができる。
pub unsafe fn init_per_cpu(num_cpus: usize) {
    INITIALIZED.call_once(|| {
        let num_cpus = num_cpus.min(MAX_CPUS);

        // 1. FSGSBASEを有効化（サポートされている場合のみ）
        // SAFETY: 初期化時に一度だけ呼ばれる

        // CPUIDでFSGSBASEサポートを確認
        #[cfg(not(feature = "qemu-test-export"))]
        let fsgsbase_supported = unsafe { check_fsgsbase_support() };
        #[cfg(feature = "qemu-test-export")]
        let fsgsbase_supported = false;

        if fsgsbase_supported {
            unsafe {
                enable_fsgsbase();
            }
            // Set global adoption flag - each AP will still need to enable CR4 in setup_current_cpu
            GSBASE_FASTPATH.store(true, Ordering::Release);
        }

        // 2. BSP（CPU 0）のデータを先に初期化してGsBaseを設定
        // これにより、以降の初期化コード内でcurrent_cpu_id()が使えるようになる
        unsafe {
            // Initialize Hot/Cold structures (Phase 3)
            PER_CPU_HOT[0] = PerCpuHot::new(0);
            PER_CPU_COLD[0] = PerCpuCold::new(0);
            PER_CPU_HOT[0].set_self_ptr();
            PER_CPU_HOT[0].set_cold(&mut PER_CPU_COLD[0] as *mut PerCpuCold);

            // Legacy: Full initialization for backward compatibility
            PER_CPU_DATA[0] = PerCpuData::new(0);
            PER_CPU_DATA[0].set_self_ptr();

            // BSPのGsBaseを設定 - PER_CPU_HOT を使用（Phase 3 Hot/Cold最適化）
            let bsp_ptr = &PER_CPU_HOT[0] as *const _ as u64;
            // FSGSBASEが有効な場合は高速版、そうでなければMSR版を使用
            if fsgsbase_supported {
                write_gs_base(bsp_ptr);
            } else {
                write_gs_base_msr(bsp_ptr);
            }

            // BSPのGSBaseが設定済みであることをマーク
            BSP_GSBASE_SET.store(true, Ordering::Release);

            // 2.5. TLS (Thread Local Storage) の初期化

            #[cfg(all(not(test), not(target_os = "windows")))]
            {
                unsafe extern "C" {
                    static __tls_start: u8;
                    static __tls_end: u8;
                }

                let _tls_start = &__tls_start as *const u8 as u64;
                let tls_end = &__tls_end as *const u8 as u64;

                let fs_base = tls_end;

                if fsgsbase_supported {
                    write_fs_base(fs_base);
                } else {
                    write_fs_base_msr(fs_base);
                }
            }
            #[cfg(any(test, target_os = "windows"))]
            {
                // TLS skipped in test or Windows build
            }
        }

        // 3. 残りのCPU（AP）のデータを初期化
        let mut i = 1usize; // CPU 0は既に初期化済み
        while i < num_cpus {
            // SAFETY: 初期化中は他のCPUからアクセスされない
            // Initialize Hot/Cold structures (Phase 3)
            unsafe {
                PER_CPU_HOT[i] = PerCpuHot::new(i);
                PER_CPU_COLD[i] = PerCpuCold::new(i);
                PER_CPU_HOT[i].set_self_ptr();
                PER_CPU_HOT[i].set_cold(&mut PER_CPU_COLD[i] as *mut PerCpuCold);

                // Legacy: Full init for backward compatibility
                PER_CPU_DATA[i] = PerCpuData::new(i);
                PER_CPU_DATA[i].set_self_ptr();
            }
            i += 1;
        }

        *ACTIVE_CPUS.lock().expect("lock poisoned") = num_cpus;
        mark_cpu_online(0);
    });
}

/// 現在のCPUのPer-CPUデータを設定（AP用）
///
/// BSP（CPU 0）のGsBaseは `init_per_cpu()` 内で自動的に設定されるため、
/// この関数は主にAP（Application Processor）の起動時に使用する。
/// BSPに対して呼んでも問題ない（冪等）。
///
/// # Safety
/// - 各CPUのブート時に一度だけ呼ばれる必要がある
/// - cpu_idは有効な範囲内である必要がある
/// - init_per_cpu() が先に呼ばれている必要がある
pub unsafe fn setup_current_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }

    // If fastpath is adopted globally, enable CR4.FSGSBASE on THIS CPU
    // (CR4 is per-core, so each AP must enable it independently)
    if can_use_fsgsbase() && !is_fsgsbase_enabled() {
        unsafe {
            enable_fsgsbase();
        }
    }

    // Use addr_of! to avoid creating a reference to static mut
    let hot_slot_ptr = core::ptr::addr_of!(PER_CPU_HOT[cpu_id]) as usize;

    // Idempotent: only initialize if not already done (check self_ptr)
    if unsafe { PER_CPU_HOT[cpu_id].self_ptr } != hot_slot_ptr {
        unsafe {
            // Initialize Hot/Cold structures
            PER_CPU_HOT[cpu_id] = PerCpuHot::new(cpu_id);
            PER_CPU_COLD[cpu_id] = PerCpuCold::new(cpu_id);
            PER_CPU_HOT[cpu_id].set_self_ptr();
            PER_CPU_HOT[cpu_id].set_cold(&mut PER_CPU_COLD[cpu_id] as *mut PerCpuCold);

            // Legacy: also init PerCpuData for backward compatibility
            PER_CPU_DATA[cpu_id] = PerCpuData::new(cpu_id);
            PER_CPU_DATA[cpu_id].set_self_ptr();
        }
    }

    // Set GSBase to PER_CPU_HOT for this CPU (Phase 3 optimization)
    unsafe {
        write_gsbase_any(hot_slot_ptr as u64);
    }

    mark_cpu_online(cpu_id);
}

/// Mark a CPU as online (best-effort)
pub fn mark_cpu_online(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    let bit = 1u64 << cpu_id;
    ONLINE_CPU_MASK.fetch_or(bit, Ordering::Release);
    let mut active = ACTIVE_CPUS.lock_for_init("[PCPU] mark_cpu_online");
    if cpu_id + 1 > *active {
        *active = cpu_id + 1;
    }
}

/// Get a list of online CPU IDs
pub fn online_cpu_ids() -> Vec<usize> {
    let mask = ONLINE_CPU_MASK.load(Ordering::Acquire);
    let mut ids = Vec::new();
    for cpu_id in 0..MAX_CPUS {
        if (mask & (1u64 << cpu_id)) != 0 {
            ids.push(cpu_id);
        }
    }
    if ids.is_empty() {
        ids.push(0);
    }
    ids
}

/// 現在のCPU IDを取得
///
/// GsBase経由でPerCpuHotからCPU IDを読み取る
/// 従来の引数渡しが不要になる
///
/// # Panics
/// GsBaseが未初期化（0または不正な値）の場合、panicする。
/// これにより setup_current_cpu() 呼び忘れを早期に検出できる。
#[inline]
pub fn current_cpu_id() -> usize {
    // Use unified helper that handles both FSGSBASE and MSR paths
    let gs_base = unsafe { read_gsbase_any() };

    // GsBaseが無効な場合は setup_current_cpu() が呼ばれていないか破損している
    if !is_valid_hot_gs_base(gs_base) {
        panic!(
            "CPU Local Storage not initialized or invalid GSBase: {:#x}. Call setup_current_cpu() first.",
            gs_base
        );
    }

    // GSBase now points to PerCpuHot (Phase 3)
    let hot_ptr = gs_base as *const PerCpuHot;

    // SAFETY: hot_ptrは有効なPerCpuHotを指す
    let hot = unsafe { &*hot_ptr };

    // self_ptrで検証：本当に有効なPerCpuHotを指しているか
    if hot.self_ptr != hot_ptr as usize {
        panic!("CPU Local Storage corrupted: self_ptr mismatch");
    }

    hot.cpu_id
}

/// 現在のCPU IDを取得（パニックしない版）
///
/// 初期化前の状態でも安全に呼べる。
/// 初期化されていない場合は None を返す。
#[inline]
pub fn try_current_cpu_id() -> Option<usize> {
    // Use unified helper - safe even before per-CPU init
    let gs_base = unsafe { read_gsbase_any() };
    if !is_valid_hot_gs_base(gs_base) {
        return None;
    }

    // GSBase now points to PerCpuHot (Phase 3)
    let hot_ptr = gs_base as *const PerCpuHot;
    let hot = unsafe { &*hot_ptr };

    // 検証
    if hot.self_ptr != hot_ptr as usize {
        return None;
    }

    Some(hot.cpu_id)
}

/// 現在のCPUの Legacy Per-CPUデータへの参照を取得
///
/// GSBase は PerCpuHot を指すため、cpu_id 経由で PER_CPU_DATA を引く
///
/// # Safety
/// init_per_cpu() が呼ばれている必要がある
#[inline]
pub unsafe fn current_per_cpu() -> Option<&'static PerCpuData> {
    // Get cpu_id from Hot (GSBase -> PerCpuHot)
    let hot = current_per_cpu_hot()?;
    let cpu = hot.cpu_id;
    if cpu >= MAX_CPUS {
        return None;
    }

    // Access legacy PER_CPU_DATA via cpu_id
    let ptr = core::ptr::addr_of!(PER_CPU_DATA[cpu]);
    let pc = &*ptr;

    // Validate legacy self_ptr as well
    if pc.self_ptr != ptr as usize {
        return None;
    }

    Some(pc)
}

/// 現在のCPUの Legacy Per-CPUデータへの可変参照を取得
///
/// GSBase は PerCpuHot を指すため、cpu_id 経由で PER_CPU_DATA を引く
///
/// # Safety
/// - init_per_cpu() が呼ばれている必要がある
/// - 同時に複数の可変参照を取得してはならない
#[inline]
pub unsafe fn current_per_cpu_mut() -> Option<&'static mut PerCpuData> {
    // Get cpu_id from Hot (GSBase -> PerCpuHot)
    let hot = current_per_cpu_hot()?;
    let cpu = hot.cpu_id;
    if cpu >= MAX_CPUS {
        return None;
    }

    // Access legacy PER_CPU_DATA via cpu_id
    let ptr = core::ptr::addr_of_mut!(PER_CPU_DATA[cpu]);
    let pc = &mut *ptr;

    // Validate legacy self_ptr as well
    if pc.self_ptr != ptr as usize {
        return None;
    }

    Some(pc)
}

/// 特定のCPUのPer-CPUデータへの参照を取得
///
/// # Safety
/// cpu_idは有効な範囲内である必要がある
pub unsafe fn get_per_cpu(cpu_id: usize) -> Option<&'static PerCpuData> {
    if cpu_id >= MAX_CPUS {
        return None;
    }

    let active = *ACTIVE_CPUS.lock().expect("lock poisoned");
    if cpu_id >= active {
        return None;
    }

    // SAFETY: cpu_idは有効範囲内
    unsafe { Some(&PER_CPU_DATA[cpu_id]) }
}

/// アクティブなCPU数を取得
pub fn active_cpu_count() -> usize {
    *ACTIVE_CPUS.lock().expect("lock poisoned")
}

// ============================================================================
// Global Interrupt Context Helpers
// ============================================================================

/// Check if the current CPU is executing in interrupt context.
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Returns
/// - `true` if running inside an interrupt handler (ISR)
/// - `false` if running in normal context or Per-CPU is not initialized
#[inline]
pub fn in_interrupt_context() -> bool {
    // Use PerCpuHot directly (Hot/Cold optimization)
    unsafe {
        current_per_cpu_hot()
            .map(|hot| hot.in_interrupt())
            .unwrap_or(false)
    }
}

/// Enter interrupt context (call at the start of every ISR).
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Safety
/// Must only be called from actual interrupt handler entry points.
#[inline]
pub fn enter_interrupt() {
    // Use PerCpuHot directly (Hot/Cold optimization)
    unsafe {
        if let Some(hot) = current_per_cpu_hot() {
            hot.enter_interrupt();
        }
    }
}

/// Exit interrupt context (call at the end of every ISR).
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Safety
/// Must only be called from actual interrupt handler exit points.
#[inline]
pub fn exit_interrupt() {
    // Use PerCpuHot directly (Hot/Cold optimization)
    unsafe {
        if let Some(hot) = current_per_cpu_hot() {
            hot.exit_interrupt();
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
