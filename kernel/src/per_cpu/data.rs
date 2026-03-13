use super::*;
use crate::sync::poison_lock::PoisonLock;
use alloc::alloc::{Layout, alloc_zeroed};
use alloc::vec::Vec;
use boot_proto::TlsInfo;

// Required for inline assembly macros and atomic ordering constants
use core::arch::asm;
use core::ptr;
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

/// Per-CPUデータが初期化済みかどうか
pub(crate) static INITIALIZED: spin::Once<()> = spin::Once::new();

/// 初期化済みCPU数
pub(crate) static ACTIVE_CPUS: PoisonLock<usize> = PoisonLock::new(0);
/// Online CPU bitmask (bit N set => CPU N online)
pub(crate) static ONLINE_CPU_MASK: AtomicU64 = AtomicU64::new(0);
pub(crate) static TLS_TEMPLATE_INFO: PoisonLock<Option<TlsInfo>> = PoisonLock::new(None);
pub(crate) static TLS_FS_BASES: [AtomicU64; MAX_CPUS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; MAX_CPUS]
};

/// Fastpath adoption flag: true = CPUID supports FSGSBASE and we adopt rdgsbase/wrgsbase
/// Note: This is a global adoption decision. Each CPU must still enable CR4.FSGSBASE before use.
pub(crate) static GSBASE_FASTPATH: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// BSPのGSBaseが設定済みかどうか
/// read_gsbase_any() が初期化前にMSRからゴミ値を読み取るのを防ぐ
pub(crate) static BSP_GSBASE_SET: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, target_os = "linux"))]
static TEST_GSBASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(all(test, target_os = "linux"))]
fn ensure_host_test_bootstrap() {
    INITIALIZED.call_once(|| unsafe {
        PER_CPU_HOT[0] = PerCpuHot::new(0);
        PER_CPU_COLD[0] = PerCpuCold::new(0);
        PER_CPU_HOT[0].set_self_ptr();
        PER_CPU_HOT[0].set_cold(core::ptr::addr_of_mut!(PER_CPU_COLD[0]));

        GSBASE_FASTPATH.store(false, Ordering::Release);
        BSP_GSBASE_SET.store(true, Ordering::Release);
        ONLINE_CPU_MASK.store(1, Ordering::Release);
        *ACTIVE_CPUS.lock().expect("lock poisoned") = 1;
    });

    let hot_ptr = unsafe { core::ptr::addr_of!(PER_CPU_HOT[0]) as u64 };
    TEST_GSBASE.store(hot_ptr, Ordering::Release);
    BSP_GSBASE_SET.store(true, Ordering::Release);
}

#[cfg(all(test, target_os = "linux"))]
pub fn init_for_host_tests() {
    ensure_host_test_bootstrap();
}

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
    #[cfg(all(test, target_os = "linux"))]
    {
        ensure_host_test_bootstrap();
        let gs_base = TEST_GSBASE.load(Ordering::Acquire);
        if gs_base != 0 {
            return gs_base;
        }
    }

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
    #[cfg(all(test, target_os = "linux"))]
    {
        ensure_host_test_bootstrap();
        TEST_GSBASE.store(value, Ordering::Release);
        BSP_GSBASE_SET.store(true, Ordering::Release);
        return;
    }

    if can_use_fsgsbase() && is_fsgsbase_enabled() {
        write_gs_base(value)
    } else {
        write_gs_base_msr(value)
    }
}

// ============================================================================
// Hot/Cold Per-CPU Accessors
// ============================================================================

#[inline]
fn active_cpu_limit() -> usize {
    *ACTIVE_CPUS.lock().expect("lock poisoned")
}

#[inline]
fn validate_hot_ref(cpu_id: usize) -> Option<&'static PerCpuHot> {
    if cpu_id >= MAX_CPUS || cpu_id >= active_cpu_limit() {
        return None;
    }

    let ptr = unsafe { core::ptr::addr_of!(PER_CPU_HOT[cpu_id]) };
    let hot = unsafe { &*ptr };
    (hot.self_ptr == ptr as usize).then_some(hot)
}

#[inline]
fn validate_hot_mut(cpu_id: usize) -> Option<&'static mut PerCpuHot> {
    if cpu_id >= MAX_CPUS || cpu_id >= active_cpu_limit() {
        return None;
    }

    let ptr = unsafe { core::ptr::addr_of_mut!(PER_CPU_HOT[cpu_id]) };
    let hot = unsafe { &mut *ptr };
    (hot.self_ptr == ptr as usize).then_some(hot)
}

#[inline]
fn validate_cold_ref(cpu_id: usize) -> Option<&'static PerCpuCold> {
    validate_hot_ref(cpu_id).and_then(PerCpuHot::cold_opt)
}

#[inline]
fn validate_cold_mut(cpu_id: usize) -> Option<&'static mut PerCpuCold> {
    let hot = validate_hot_mut(cpu_id)?;
    unsafe { Some(hot.cold_mut()) }
}

#[inline]
pub fn hot_for_cpu(cpu_id: usize) -> Option<&'static PerCpuHot> {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

    validate_hot_ref(cpu_id)
}

#[inline]
pub fn cold_for_cpu(cpu_id: usize) -> Option<&'static PerCpuCold> {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

    validate_cold_ref(cpu_id)
}

#[inline]
pub fn with_cpu_hot<R>(cpu_id: usize, f: impl FnOnce(&PerCpuHot) -> R) -> Option<R> {
    hot_for_cpu(cpu_id).map(f)
}

#[inline]
pub fn with_cpu_cold<R>(cpu_id: usize, f: impl FnOnce(&PerCpuCold) -> R) -> Option<R> {
    cold_for_cpu(cpu_id).map(f)
}

#[inline]
pub(crate) fn with_cpu_hot_mut<R>(cpu_id: usize, f: impl FnOnce(&mut PerCpuHot) -> R) -> Option<R> {
    validate_hot_mut(cpu_id).map(f)
}

#[inline]
pub(crate) fn with_cpu_cold_mut<R>(
    cpu_id: usize,
    f: impl FnOnce(&mut PerCpuCold) -> R,
) -> Option<R> {
    validate_cold_mut(cpu_id).map(f)
}

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

#[inline]
pub fn current_hot() -> Option<&'static PerCpuHot> {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

    unsafe { current_per_cpu_hot() }
}

#[inline]
pub fn current_cold() -> Option<&'static PerCpuCold> {
    current_hot().and_then(PerCpuHot::cold_opt)
}

#[inline]
pub fn with_current_hot<R>(f: impl FnOnce(&PerCpuHot) -> R) -> Option<R> {
    current_hot().map(f)
}

#[inline]
pub fn with_current_cold<R>(f: impl FnOnce(&PerCpuCold) -> R) -> Option<R> {
    current_cold().map(f)
}

#[inline]
pub fn with_current_hot_mut<R>(f: impl FnOnce(&mut PerCpuHot) -> R) -> Option<R> {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

    let cpu_id = try_current_cpu_id()?;
    with_cpu_hot_mut(cpu_id, f)
}

#[inline]
pub fn with_current_cold_mut<R>(f: impl FnOnce(&mut PerCpuCold) -> R) -> Option<R> {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

    let cpu_id = try_current_cpu_id()?;
    with_cpu_cold_mut(cpu_id, f)
}

/// Check if a CPU is online
pub fn is_cpu_online(cpu_id: usize) -> bool {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

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

#[inline]
unsafe fn write_fsbase_any(value: u64) {
    if can_use_fsgsbase() && is_fsgsbase_enabled() {
        unsafe {
            write_fs_base(value);
        }
    } else {
        unsafe {
            write_fs_base_msr(value);
        }
    }
}

fn record_tls_template(tls_template: Option<&TlsInfo>) {
    let mut guard = TLS_TEMPLATE_INFO.lock_for_init("[PCPU] record_tls_template");
    *guard = tls_template
        .copied()
        .filter(|info| info.start_addr != 0 && info.mem_size != 0);
}

fn tls_template() -> Option<TlsInfo> {
    *TLS_TEMPLATE_INFO.lock().expect("lock poisoned")
}

#[cfg(all(not(test), not(target_os = "windows")))]
unsafe fn allocate_tls_for_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS || TLS_FS_BASES[cpu_id].load(Ordering::Acquire) != 0 {
        return;
    }

    let Some(tls) = tls_template() else {
        return;
    };

    let mem_size = tls.mem_size as usize;
    let file_size = core::cmp::min(tls.file_size as usize, mem_size);
    if mem_size == 0 {
        return;
    }

    let mut align = core::cmp::max(tls.align as usize, core::mem::align_of::<usize>());
    if !align.is_power_of_two() {
        align = align.next_power_of_two();
    }

    let alloc_size = match mem_size.checked_add(align) {
        Some(size) => size,
        None => return,
    };
    let layout = match Layout::from_size_align(alloc_size, align) {
        Ok(layout) => layout,
        Err(_) => return,
    };
    let raw = unsafe { alloc_zeroed(layout) };
    if raw.is_null() {
        return;
    }

    let aligned = (raw as usize + (align - 1)) & !(align - 1);
    if file_size > 0 {
        unsafe {
            ptr::copy_nonoverlapping(tls.start_addr as *const u8, aligned as *mut u8, file_size);
        }
    }

    let fs_base = aligned.saturating_add(mem_size) as u64;
    TLS_FS_BASES[cpu_id].store(fs_base, Ordering::Release);
}

#[cfg(any(test, target_os = "windows"))]
unsafe fn allocate_tls_for_cpu(_cpu_id: usize) {}

unsafe fn install_tls_for_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }

    unsafe {
        allocate_tls_for_cpu(cpu_id);
    }

    let fs_base = TLS_FS_BASES[cpu_id].load(Ordering::Acquire);
    if fs_base != 0 {
        unsafe {
            write_fsbase_any(fs_base);
        }
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
pub unsafe fn init_bsp_per_cpu(tls_template: Option<&TlsInfo>) {
    INITIALIZED.call_once(|| {
        // 1. FSGSBASEを有効化（サポートされている場合のみ）
        #[cfg(not(feature = "qemu-test-export"))]
        let fsgsbase_supported = unsafe { check_fsgsbase_support() };
        #[cfg(feature = "qemu-test-export")]
        let fsgsbase_supported = false;

        if fsgsbase_supported {
            unsafe {
                enable_fsgsbase();
            }
            GSBASE_FASTPATH.store(true, Ordering::Release);
        }

        unsafe {
            PER_CPU_HOT[0] = PerCpuHot::new(0);
            PER_CPU_COLD[0] = PerCpuCold::new(0);
            PER_CPU_HOT[0].set_self_ptr();
            PER_CPU_HOT[0].set_cold(&mut PER_CPU_COLD[0] as *mut PerCpuCold);

            let bsp_ptr = &PER_CPU_HOT[0] as *const _ as u64;
            if fsgsbase_supported {
                write_gs_base(bsp_ptr);
            } else {
                write_gs_base_msr(bsp_ptr);
            }

            BSP_GSBASE_SET.store(true, Ordering::Release);
            record_tls_template(tls_template);
            install_tls_for_cpu(0);
        }

        *ACTIVE_CPUS.lock().expect("lock poisoned") = 1;
        mark_cpu_online(0);
    });
}

pub fn finalize_cpu_topology(num_cpus: usize) {
    let num_cpus = num_cpus.min(MAX_CPUS).max(1);
    if INITIALIZED.get().is_none() {
        return;
    }

    let mut i = 1usize;
    while i < num_cpus {
        unsafe {
            PER_CPU_HOT[i] = PerCpuHot::new(i);
            PER_CPU_COLD[i] = PerCpuCold::new(i);
            PER_CPU_HOT[i].set_self_ptr();
            PER_CPU_HOT[i].set_cold(&mut PER_CPU_COLD[i] as *mut PerCpuCold);
            allocate_tls_for_cpu(i);
        }
        i += 1;
    }
}

pub unsafe fn init_per_cpu(num_cpus: usize) {
    unsafe {
        init_bsp_per_cpu(None);
    }
    finalize_cpu_topology(num_cpus);
}

pub unsafe fn register_current_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }

    if can_use_fsgsbase() && !is_fsgsbase_enabled() {
        unsafe {
            enable_fsgsbase();
        }
    }

    let hot_slot_ptr = core::ptr::addr_of!(PER_CPU_HOT[cpu_id]) as usize;
    if unsafe { PER_CPU_HOT[cpu_id].self_ptr } != hot_slot_ptr {
        unsafe {
            PER_CPU_HOT[cpu_id] = PerCpuHot::new(cpu_id);
            PER_CPU_COLD[cpu_id] = PerCpuCold::new(cpu_id);
            PER_CPU_HOT[cpu_id].set_self_ptr();
            PER_CPU_HOT[cpu_id].set_cold(&mut PER_CPU_COLD[cpu_id] as *mut PerCpuCold);
        }
    }

    unsafe {
        write_gsbase_any(hot_slot_ptr as u64);
        install_tls_for_cpu(cpu_id);
    }

    mark_cpu_online(cpu_id);
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
    unsafe { register_current_cpu(cpu_id) };
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
    crate::smp::set_cpu_lifecycle_stage(cpu_id, crate::smp::CpuLifecycleStage::PerCpuReady);
}

/// Get a list of online CPU IDs
pub fn online_cpu_ids() -> Vec<usize> {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

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

/// アクティブなCPU数を取得
pub fn active_cpu_count() -> usize {
    #[cfg(all(test, target_os = "linux"))]
    ensure_host_test_bootstrap();

    core::cmp::max(
        *ACTIVE_CPUS.lock().expect("lock poisoned"),
        crate::smp::cpu_count() as usize,
    )
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
    current_hot().map(PerCpuHot::in_interrupt).unwrap_or(false)
}

/// Enter interrupt context (call at the start of every ISR).
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Safety
/// Must only be called from actual interrupt handler entry points.
#[inline]
pub fn enter_interrupt() {
    let _ = with_current_hot(|hot| hot.enter_interrupt());
}

/// Exit interrupt context (call at the end of every ISR).
///
/// Uses PerCpuHot directly for fast access (Hot/Cold optimization).
///
/// # Safety
/// Must only be called from actual interrupt handler exit points.
#[inline]
pub fn exit_interrupt() {
    let _ = with_current_hot(|hot| hot.exit_interrupt());
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
