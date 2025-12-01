// ============================================================================
// src/mm/per_cpu.rs - Per-CPU Data using GsBase Register
// 設計書 5.2: コアローカルな高速データアクセス
//
// GsBaseレジスタの活用:
// - x86_64ではGsBaseをPer-CPUデータのベースポインタとして使用
// - コンテキストスイッチ時に自動的に切り替わる（または手動設定）
// - cpu_id引数が不要になり、APIが簡素化
// ============================================================================
use core::arch::asm;
use core::ptr::NonNull;
use core::alloc::Layout;
use spin::Mutex;

/// Per-CPUデータ構造
/// GsBaseからのオフセットでアクセス
#[repr(C, align(64))]
pub struct PerCpuData {
    /// 自己参照ポインタ（検証用）
    pub self_ptr: usize,
    /// CPU ID
    pub cpu_id: usize,
    /// 現在実行中のタスクID（将来用）
    pub current_task_id: u64,
    /// Per-CPUヒープ統計
    pub alloc_count: u64,
    pub dealloc_count: u64,
    /// パディング（キャッシュラインに揃える）
    _padding: [u64; 3],
}

impl PerCpuData {
    /// 新しいPer-CPUデータを作成
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            self_ptr: 0,
            cpu_id,
            current_task_id: 0,
            alloc_count: 0,
            dealloc_count: 0,
            _padding: [0; 3],
        }
    }
    
    /// 自己参照ポインタを設定
    pub fn set_self_ptr(&mut self) {
        self.self_ptr = self as *const _ as usize;
    }
}

/// 最大CPU数
pub const MAX_CPUS: usize = 64;

/// 静的に確保されたPer-CPUデータ配列
/// 各CPUに対応するデータが格納される
static mut PER_CPU_DATA: [PerCpuData; MAX_CPUS] = {
    const INIT: PerCpuData = PerCpuData::new(0);
    [INIT; MAX_CPUS]
};

/// Per-CPUデータが初期化済みかどうか
static INITIALIZED: spin::Once<()> = spin::Once::new();

/// 初期化済みCPU数
static ACTIVE_CPUS: Mutex<usize> = Mutex::new(0);

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

/// Per-CPUシステムを初期化
/// 
/// # Safety
/// - カーネル初期化時に一度だけ呼ばれる必要がある
/// - BSP（ブートストラッププロセッサ）から呼ぶ
pub unsafe fn init_per_cpu(num_cpus: usize) {
    INITIALIZED.call_once(|| {
        let num_cpus = num_cpus.min(MAX_CPUS);
        
        // FSGSBASEを有効化
        // SAFETY: 初期化時に一度だけ呼ばれる
        unsafe { enable_fsgsbase(); }
        
        // 各CPUのデータを初期化
        for cpu_id in 0..num_cpus {
            // SAFETY: 初期化中は他のCPUからアクセスされない
            unsafe {
                PER_CPU_DATA[cpu_id] = PerCpuData::new(cpu_id);
                PER_CPU_DATA[cpu_id].set_self_ptr();
            }
        }
        
        *ACTIVE_CPUS.lock() = num_cpus;
    });
}

/// 現在のCPUのPer-CPUデータを設定
/// 
/// # Safety
/// - 各CPUのブート時に一度だけ呼ばれる必要がある
/// - cpu_idは有効な範囲内である必要がある
pub unsafe fn setup_current_cpu(cpu_id: usize) {
    if cpu_id >= MAX_CPUS {
        return;
    }
    
    // SAFETY: cpu_idは有効範囲内
    let per_cpu_ptr = unsafe { &PER_CPU_DATA[cpu_id] as *const _ as u64 };
    
    // GsBaseを設定（FSGSBASEが有効な場合は高速版を使用）
    if is_fsgsbase_enabled() {
        // SAFETY: per_cpu_ptrは有効なPer-CPUデータを指す
        unsafe { write_gs_base(per_cpu_ptr); }
    } else {
        // SAFETY: MSR版でGsBaseを設定
        unsafe { write_gs_base_msr(per_cpu_ptr); }
    }
}

/// 現在のCPU IDを取得
/// 
/// GsBase経由でPer-CPUデータからCPU IDを読み取る
/// 従来の引数渡しが不要になる
/// 
/// # Panics
/// GsBaseが未初期化（0または不正な値）の場合、panicする。
/// これにより setup_current_cpu() 呼び忘れを早期に検出できる。
#[inline]
pub fn current_cpu_id() -> usize {
    // FSGSBASEが有効でない場合は初期化前と判断してpanic
    if !is_fsgsbase_enabled() {
        panic!("CPU Local Storage not initialized: FSGSBASE not enabled");
    }
    
    // SAFETY: GsBaseを読み取り
    let gs_base = unsafe { read_gs_base() };
    
    // GsBaseが0の場合は setup_current_cpu() が呼ばれていない
    if gs_base == 0 {
        panic!("CPU Local Storage not initialized: GsBase is null. Call setup_current_cpu() first.");
    }
    
    let per_cpu_ptr = gs_base as *const PerCpuData;
    
    // SAFETY: per_cpu_ptrは有効なPerCpuDataを指す
    let per_cpu = unsafe { &*per_cpu_ptr };
    
    // self_ptrで検証：本当に有効なPerCpuDataを指しているか
    if per_cpu.self_ptr != per_cpu_ptr as usize {
        panic!("CPU Local Storage corrupted: self_ptr mismatch");
    }
    
    per_cpu.cpu_id
}

/// 現在のCPU IDを取得（パニックしない版）
/// 
/// 初期化前の状態でも安全に呼べる。
/// 初期化されていない場合は None を返す。
#[inline]
pub fn try_current_cpu_id() -> Option<usize> {
    if !is_fsgsbase_enabled() {
        return None;
    }
    
    let gs_base = unsafe { read_gs_base() };
    if gs_base == 0 {
        return None;
    }
    
    let per_cpu_ptr = gs_base as *const PerCpuData;
    let per_cpu = unsafe { &*per_cpu_ptr };
    
    // 検証
    if per_cpu.self_ptr != per_cpu_ptr as usize {
        return None;
    }
    
    Some(per_cpu.cpu_id)
}

/// 現在のCPUのPer-CPUデータへの参照を取得
/// 
/// # Safety
/// GsBaseが有効なPer-CPUデータを指している必要がある
#[inline]
pub unsafe fn current_per_cpu() -> Option<&'static PerCpuData> {
    if !is_fsgsbase_enabled() {
        return None;
    }
    
    // SAFETY: GsBaseは初期化済みのPer-CPUデータを指している
    let per_cpu_ptr = unsafe { read_gs_base() } as *const PerCpuData;
    
    if per_cpu_ptr.is_null() {
        return None;
    }
    
    // SAFETY: per_cpu_ptrは有効なPerCpuDataを指す
    unsafe { Some(&*per_cpu_ptr) }
}

/// 現在のCPUのPer-CPUデータへの可変参照を取得
/// 
/// # Safety
/// - GsBaseが有効なPer-CPUデータを指している必要がある
/// - 同時に複数の可変参照を取得してはならない
#[inline]
pub unsafe fn current_per_cpu_mut() -> Option<&'static mut PerCpuData> {
    if !is_fsgsbase_enabled() {
        return None;
    }
    
    // SAFETY: GsBaseは初期化済みのPer-CPUデータを指している
    let per_cpu_ptr = unsafe { read_gs_base() } as *mut PerCpuData;
    
    if per_cpu_ptr.is_null() {
        return None;
    }
    
    // SAFETY: 呼び出し元が排他的アクセスを保証
    unsafe { Some(&mut *per_cpu_ptr) }
}

/// 特定のCPUのPer-CPUデータへの参照を取得
/// 
/// # Safety
/// cpu_idは有効な範囲内である必要がある
pub unsafe fn get_per_cpu(cpu_id: usize) -> Option<&'static PerCpuData> {
    if cpu_id >= MAX_CPUS {
        return None;
    }
    
    let active = *ACTIVE_CPUS.lock();
    if cpu_id >= active {
        return None;
    }
    
    // SAFETY: cpu_idは有効範囲内
    unsafe { Some(&PER_CPU_DATA[cpu_id]) }
}

/// アクティブなCPU数を取得
pub fn active_cpu_count() -> usize {
    *ACTIVE_CPUS.lock()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_per_cpu_data_layout() {
        // Per-CPUデータがキャッシュラインにアラインされていることを確認
        assert_eq!(core::mem::align_of::<PerCpuData>(), 64);
        
        // サイズが1キャッシュライン以内であることを確認
        assert!(core::mem::size_of::<PerCpuData>() <= 64);
    }
}
