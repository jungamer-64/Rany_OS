// ============================================================================
// src/task/context.rs - Context Switch Implementation
// 設計書 4.3: プリエンプティブマルチタスキング
//
// x86_64 のレジスタ退避・復帰、スタック切り替えを実装
// ============================================================================
use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::boxed::Box;
use x86_64::VirtAddr;

/// タスク状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// 実行可能
    Ready = 0,
    /// 実行中
    Running = 1,
    /// ブロック中（I/O待ち等）
    Blocked = 2,
    /// 終了済み
    Terminated = 3,
}

/// CPUコンテキスト（レジスタ状態）
/// 
/// x86_64 ABI に従い、callee-saved レジスタのみ保存
/// caller-saved (rax, rcx, rdx, r8-r11) は関数呼び出しで破壊されるため不要
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuContext {
    // Callee-saved registers
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    
    // スタックポインタ
    pub rsp: u64,
    
    // 命令ポインタ（ret先アドレス）
    pub rip: u64,
    
    // フラグレジスタ
    pub rflags: u64,
}

impl CpuContext {
    /// 空のコンテキストを作成
    pub const fn empty() -> Self {
        Self {
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rsp: 0,
            rip: 0,
            rflags: 0x200, // 割り込み有効 (IF=1)
        }
    }
    
    /// 新しいタスク用のコンテキストを作成
    /// 
    /// # Arguments
    /// * `entry_point` - タスクのエントリポイント関数
    /// * `stack_top` - スタックの最上位アドレス（高いアドレス側）
    /// * `arg` - タスクに渡す引数
    pub fn new_task(entry_point: fn(u64) -> !, stack_top: VirtAddr, arg: u64) -> Self {
        let stack = stack_top.as_u64();
        
        // スタック上にリターンアドレスとして task_wrapper を配置
        // task_wrapper が entry_point(arg) を呼び出す
        Self {
            rbx: 0,
            rbp: 0,
            r12: entry_point as u64,  // r12 にエントリポイントを保存
            r13: arg,                  // r13 に引数を保存
            r14: 0,
            r15: 0,
            rsp: stack - 8,           // リターンアドレス分を確保
            rip: task_entry_trampoline as *const () as u64,
            rflags: 0x200,            // IF=1 (割り込み有効)
        }
    }
}

/// タスクエントリ用のトランポリン関数
/// 
/// コンテキストスイッチ後に最初に実行される
/// r12 = entry_point, r13 = arg として呼び出される
#[unsafe(naked)]
unsafe extern "C" fn task_entry_trampoline() -> ! {
    naked_asm!(
        // r13 (arg) を rdi に移動（第1引数）
        "mov rdi, r13",
        // r12 (entry_point) を呼び出し
        "call r12",
        // 戻ってこないはずだが、念のため
        "ud2",
    )
}

/// コンテキストスイッチを実行
/// 
/// 現在のタスクのコンテキストを `old` に保存し、
/// `new` のコンテキストを復元して実行を再開する。
/// 
/// # Safety
/// - `old` と `new` は有効な CpuContext へのポインタである必要がある
/// - スタックは適切に設定されている必要がある
#[unsafe(naked)]
pub unsafe extern "C" fn switch_context(_old: *mut CpuContext, _new: *const CpuContext) {
    naked_asm!(
        // ========================================
        // 現在のコンテキストを old (rdi) に保存
        // ========================================
        // callee-saved レジスタを保存
        "mov [rdi + 0x00], rbx",
        "mov [rdi + 0x08], rbp",
        "mov [rdi + 0x10], r12",
        "mov [rdi + 0x18], r13",
        "mov [rdi + 0x20], r14",
        "mov [rdi + 0x28], r15",
        
        // RSP を保存
        "mov [rdi + 0x30], rsp",
        
        // RIP（リターンアドレス）を保存
        // switch_context から戻る際のアドレス
        "lea rax, [rip + 2f]",
        "mov [rdi + 0x38], rax",
        
        // RFLAGS を保存
        "pushfq",
        "pop rax",
        "mov [rdi + 0x40], rax",
        
        // ========================================
        // new (rsi) のコンテキストを復元
        // ========================================
        // callee-saved レジスタを復元
        "mov rbx, [rsi + 0x00]",
        "mov rbp, [rsi + 0x08]",
        "mov r12, [rsi + 0x10]",
        "mov r13, [rsi + 0x18]",
        "mov r14, [rsi + 0x20]",
        "mov r15, [rsi + 0x28]",
        
        // RSP を復元
        "mov rsp, [rsi + 0x30]",
        
        // RFLAGS を復元
        "mov rax, [rsi + 0x40]",
        "push rax",
        "popfq",
        
        // RIP へジャンプ（新しいタスクの実行を再開）
        "jmp [rsi + 0x38]",
        
        // switch_context からの戻り先（old タスクが再開される時）
        "2:",
        "ret",
    )
}

/// カーネルタスク用のスタック
/// 
/// Per-Task スタック管理。各タスクは独自のカーネルスタックを持つ。
pub struct KernelStack {
    /// スタックメモリ（底から上に向かって成長）
    memory: Box<[u8; Self::SIZE]>,
}

impl KernelStack {
    /// スタックサイズ（16KiB）
    pub const SIZE: usize = 16 * 1024;
    
    /// ガードページサイズ（スタックオーバーフロー検出用）
    pub const GUARD_SIZE: usize = 4096;
    
    /// 新しいスタックを割り当て
    pub fn new() -> Option<Self> {
        // ゼロ初期化されたスタックメモリを確保
        // Box::new_zeroed() は allocator_api feature が必要なので代替実装
        let layout = core::alloc::Layout::new::<[u8; Self::SIZE]>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        
        if ptr.is_null() {
            return None;
        }
        
        // SAFETY: ptr は適切なサイズとアラインメントで割り当てられている
        let memory = unsafe { Box::from_raw(ptr as *mut [u8; Self::SIZE]) };
        
        Some(Self { memory })
    }
    
    /// スタックの最上位アドレス（初期RSP）を取得
    /// 
    /// x86_64 ではスタックは下方向に成長するため、
    /// 最上位アドレスが初期スタックポインタとなる
    pub fn top(&self) -> VirtAddr {
        let ptr = self.memory.as_ptr() as u64;
        let top = ptr + Self::SIZE as u64;
        
        // 16バイトアラインメント（ABI要件）
        VirtAddr::new(top & !0xF)
    }
    
    /// スタックの底アドレスを取得
    pub fn bottom(&self) -> VirtAddr {
        VirtAddr::new(self.memory.as_ptr() as u64)
    }
}

impl Default for KernelStack {
    fn default() -> Self {
        Self::new().expect("Failed to allocate kernel stack")
    }
}

/// タスク制御ブロック (TCB)
/// 
/// 各タスクの状態を管理する中心的なデータ構造
pub struct TaskControlBlock {
    /// タスクID
    pub id: super::TaskId,
    /// タスク状態
    pub state: TaskState,
    /// CPUコンテキスト
    pub context: CpuContext,
    /// カーネルスタック
    pub kernel_stack: KernelStack,
    /// 優先度（0が最高）
    pub priority: u8,
    /// CPU時間統計（ティック数）
    pub cpu_time: u64,
    /// 最後に実行されたCPU
    pub last_cpu: Option<usize>,
}

impl TaskControlBlock {
    /// 新しいTCBを作成
    pub fn new(
        entry_point: fn(u64) -> !,
        arg: u64,
        priority: u8,
    ) -> Option<Self> {
        let kernel_stack = KernelStack::new()?;
        let stack_top = kernel_stack.top();
        
        let context = CpuContext::new_task(entry_point, stack_top, arg);
        
        Some(Self {
            id: super::TaskId::new(),
            state: TaskState::Ready,
            context,
            kernel_stack,
            priority,
            cpu_time: 0,
            last_cpu: None,
        })
    }
    
    /// アイドルタスク用のTCBを作成
    pub fn idle(cpu_id: usize) -> Self {
        Self {
            id: super::TaskId::new(),
            state: TaskState::Running,
            context: CpuContext::empty(),
            kernel_stack: KernelStack::default(),
            priority: 255, // 最低優先度
            cpu_time: 0,
            last_cpu: Some(cpu_id),
        }
    }
}

// ============================================================================
// Per-CPU 現在タスク管理
// ============================================================================

use crate::sync::IrqMutex;

/// Send を実装した TCB ポインタのラッパー
/// 
/// 生ポインタは Send を実装しないが、TCB へのアクセスは
/// IrqMutex で保護されているため、安全に Send を実装できる
#[derive(Clone, Copy)]
struct TcbPtr(*mut TaskControlBlock);

// SAFETY: TcbPtr へのアクセスは IrqMutex で保護されている
unsafe impl Send for TcbPtr {}

/// 各CPUの現在実行中タスク
static CURRENT_TASKS: [IrqMutex<Option<TcbPtr>>; 64] = {
    const INIT: IrqMutex<Option<TcbPtr>> = IrqMutex::new(None);
    [INIT; 64]
};

/// 現在のCPUで実行中のタスクを設定
/// 
/// # Safety
/// tcb は有効な TaskControlBlock へのポインタである必要がある
pub unsafe fn set_current_task(cpu_id: usize, tcb: *mut TaskControlBlock) {
    if cpu_id < 64 {
        *CURRENT_TASKS[cpu_id].lock() = Some(TcbPtr(tcb));
    }
}

/// 現在のCPUで実行中のタスクを取得
pub fn get_current_task(cpu_id: usize) -> Option<*mut TaskControlBlock> {
    if cpu_id < 64 {
        CURRENT_TASKS[cpu_id].lock().map(|p| p.0)
    } else {
        None
    }
}

/// コンテキストスイッチ統計
pub static CONTEXT_SWITCH_COUNT: AtomicU64 = AtomicU64::new(0);

/// スケジューラからのコンテキストスイッチ
/// 
/// # Safety
/// - current と next は有効な TCB へのポインタである必要がある
/// - 割り込みが適切に管理されている必要がある
pub unsafe fn schedule_switch(
    cpu_id: usize,
    current: *mut TaskControlBlock,
    next: *mut TaskControlBlock,
) {
    if current == next {
        return; // 同じタスクなら何もしない
    }
    
    // 統計更新
    CONTEXT_SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
    
    // 状態更新
    // SAFETY: current と next は有効なポインタ
    unsafe {
        (*current).state = TaskState::Ready;
        (*next).state = TaskState::Running;
        (*next).last_cpu = Some(cpu_id);
        
        // 現在タスクを更新
        set_current_task(cpu_id, next);
        
        // コンテキストスイッチ実行
        switch_context(&mut (*current).context, &(*next).context);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_context_size() {
        // CpuContext のサイズが期待通りか確認
        assert_eq!(core::mem::size_of::<CpuContext>(), 72); // 9 * 8 bytes
    }
    
    #[test]
    fn test_context_alignment() {
        // 8バイトアラインメント
        assert_eq!(core::mem::align_of::<CpuContext>(), 8);
    }
}
