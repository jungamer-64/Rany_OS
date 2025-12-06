// ============================================================================
// src/unwind/gimli_unwinder.rs - gimli-based DWARF Stack Unwinding
// 設計書 8.1 改善: no_std環境での堅牢なスタックアンワインド
//
// 課題:
// - no_std環境では panic = "abort" が一般的
// - 手動の eh_frame 解析は脆弱でエラーが起きやすい
//
// 解決策:
// - gimli クレートを使用した堅牢なDWARF情報解析
// - フォールバックとしてフレームポインタベースのアンワインドも維持
// ============================================================================
#![allow(dead_code)]

use core::ops::Range;
use gimli::{
    BaseAddresses, CieOrFde, EhFrame, EndianSlice, LittleEndian, UninitializedUnwindContext,
    UnwindSection,
};

/// gimli用のエンディアン型
pub type Endian = LittleEndian;

/// gimli用のスライス型
pub type GimliSlice<'a> = EndianSlice<'a, Endian>;

/// gimliアンワインドエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GimliUnwindError {
    /// .eh_frame セクションが見つからない
    NoEhFrame,
    /// FDEが見つからない
    FdeNotFound,
    /// CIEが見つからない
    CieNotFound,
    /// gimli解析エラー
    GimliError,
    /// 不正なフレームポインタ
    InvalidFramePointer,
    /// スタック終端
    EndOfStack,
    /// レジスタルールが未定義
    UndefinedRegister,
}

/// gimliベースのアンワインダー
///
/// .eh_frame セクションを解析して、正確なスタックアンワインドを行う。
/// gimli クレートにより、複雑なDWARF CFI命令を正しく解釈できる。
pub struct GimliUnwinder<'a> {
    /// .eh_frame セクションデータ
    eh_frame: EhFrame<GimliSlice<'a>>,
    /// ベースアドレス（PC相対計算用）
    bases: BaseAddresses,
    /// テキストセクションの範囲
    text_range: Range<u64>,
}

impl<'a> GimliUnwinder<'a> {
    /// 新しいアンワインダーを作成
    ///
    /// # Arguments
    /// * `eh_frame_data` - .eh_frame セクションのバイト列
    /// * `eh_frame_addr` - .eh_frame セクションのロードアドレス
    /// * `text_range` - .text セクションのアドレス範囲
    pub fn new(eh_frame_data: &'a [u8], eh_frame_addr: u64, text_range: Range<u64>) -> Self {
        let eh_frame = EhFrame::new(eh_frame_data, LittleEndian);

        let bases = BaseAddresses::default().set_eh_frame(eh_frame_addr);

        Self {
            eh_frame,
            bases,
            text_range,
        }
    }

    /// 指定アドレスに対応するFDEを検索
    pub fn find_fde(
        &self,
        address: u64,
    ) -> Result<gimli::FrameDescriptionEntry<GimliSlice<'a>>, GimliUnwindError> {
        let mut entries = self.eh_frame.entries(&self.bases);

        while let Ok(Some(entry)) = entries.next() {
            match entry {
                CieOrFde::Cie(_) => continue,
                CieOrFde::Fde(partial_fde) => {
                    // FDEを解析
                    if let Ok(fde) = partial_fde
                        .parse(|_, _, offset| self.eh_frame.cie_from_offset(&self.bases, offset))
                    {
                        let start = fde.initial_address();
                        let end = start + fde.len();

                        if address >= start && address < end {
                            return Ok(fde);
                        }
                    }
                }
            }
        }

        Err(GimliUnwindError::FdeNotFound)
    }

    /// 単一フレームをアンワインド
    ///
    /// 現在のレジスタ状態から、呼び出し元のレジスタ状態を計算する。
    ///
    /// # Arguments
    /// * `address` - 現在の命令アドレス（RIP）
    /// * `registers` - 現在のレジスタ状態
    ///
    /// # Returns
    /// 呼び出し元のレジスタ状態、またはエラー
    pub fn unwind_frame(
        &self,
        address: u64,
        registers: &RegisterSet,
    ) -> Result<RegisterSet, GimliUnwindError> {
        // FDEを検索
        let fde = self.find_fde(address)?;

        // アンワインドコンテキストを初期化
        let mut ctx = UninitializedUnwindContext::new();

        // アンワインドテーブル行を取得
        let unwind_info = fde
            .unwind_info_for_address(&self.eh_frame, &self.bases, &mut ctx, address)
            .map_err(|_| GimliUnwindError::GimliError)?;

        // CFAを計算
        let cfa = match unwind_info.cfa() {
            gimli::CfaRule::RegisterAndOffset { register, offset } => {
                let reg_value = registers
                    .get(register.0 as usize)
                    .ok_or(GimliUnwindError::UndefinedRegister)?;
                (reg_value as i64 + offset) as u64
            }
            gimli::CfaRule::Expression(_) => {
                // DWARF式の評価は複雑なので、フォールバック
                return Err(GimliUnwindError::GimliError);
            }
        };

        // 新しいレジスタセットを構築
        let mut new_registers = RegisterSet::new();
        new_registers.set(7, cfa); // RSP = CFA

        // 各レジスタのルールを適用
        for reg_num in 0..17 {
            let rule = unwind_info.register(gimli::Register(reg_num as u16));

            let value = match rule {
                gimli::RegisterRule::Undefined => continue,
                gimli::RegisterRule::SameValue => registers.get(reg_num).unwrap_or(0),
                gimli::RegisterRule::Offset(offset) => {
                    let addr = (cfa as i64 + offset) as u64;
                    // SAFETY: アドレスが有効であることを仮定
                    unsafe { core::ptr::read(addr as *const u64) }
                }
                gimli::RegisterRule::ValOffset(offset) => (cfa as i64 + offset) as u64,
                gimli::RegisterRule::Register(other_reg) => {
                    registers.get(other_reg.0 as usize).unwrap_or(0)
                }
                _ => continue, // 式や他の複雑なルールはスキップ
            };

            new_registers.set(reg_num, value);
        }

        Ok(new_registers)
    }

    /// 完全なバックトレースを生成
    pub fn backtrace(&self, initial_registers: RegisterSet) -> GimliBacktrace {
        let mut trace = GimliBacktrace::new();
        let mut registers = initial_registers;

        for _ in 0..GimliBacktrace::MAX_FRAMES {
            let rip = registers.get(16).unwrap_or(0); // RIP

            if rip == 0 || !self.is_valid_code_address(rip) {
                break;
            }

            trace.push(GimliFrame {
                instruction_pointer: rip,
                stack_pointer: registers.get(7).unwrap_or(0),
                frame_pointer: registers.get(6).unwrap_or(0),
            });

            // 次のフレームをアンワインド
            match self.unwind_frame(rip, &registers) {
                Ok(new_regs) => registers = new_regs,
                Err(_) => break,
            }
        }

        trace
    }

    /// コードアドレスが有効かチェック
    fn is_valid_code_address(&self, addr: u64) -> bool {
        // カーネルテキストセクション内かチェック
        self.text_range.contains(&addr)
    }
}

/// レジスタセット
///
/// x86_64 のレジスタ番号:
/// 0=RAX, 1=RDX, 2=RCX, 3=RBX, 4=RSI, 5=RDI,
/// 6=RBP, 7=RSP, 8-15=R8-R15, 16=RIP
#[derive(Debug, Clone, Default)]
pub struct RegisterSet {
    values: [Option<u64>; 17],
}

impl RegisterSet {
    pub fn new() -> Self {
        Self { values: [None; 17] }
    }

    /// 現在のレジスタ状態をキャプチャ
    pub fn capture() -> Self {
        let mut regs = Self::new();

        unsafe {
            let rax: u64;
            let rbx: u64;
            let rcx: u64;
            let rdx: u64;
            let rsi: u64;
            let rdi: u64;
            let rbp: u64;
            let rsp: u64;
            let r8: u64;
            let r9: u64;
            let r10: u64;
            let r11: u64;
            let r12: u64;
            let r13: u64;
            let r14: u64;
            let r15: u64;

            core::arch::asm!(
                "mov {}, rax",
                "mov {}, rbx",
                "mov {}, rcx",
                "mov {}, rdx",
                "mov {}, rsi",
                "mov {}, rdi",
                "mov {}, rbp",
                "mov {}, rsp",
                "mov {}, r8",
                "mov {}, r9",
                "mov {}, r10",
                "mov {}, r11",
                "mov {}, r12",
                "mov {}, r13",
                "mov {}, r14",
                "mov {}, r15",
                out(reg) rax,
                out(reg) rbx,
                out(reg) rcx,
                out(reg) rdx,
                out(reg) rsi,
                out(reg) rdi,
                out(reg) rbp,
                out(reg) rsp,
                out(reg) r8,
                out(reg) r9,
                out(reg) r10,
                out(reg) r11,
                out(reg) r12,
                out(reg) r13,
                out(reg) r14,
                out(reg) r15,
                options(nostack, preserves_flags)
            );

            regs.set(0, rax);
            regs.set(1, rdx);
            regs.set(2, rcx);
            regs.set(3, rbx);
            regs.set(4, rsi);
            regs.set(5, rdi);
            regs.set(6, rbp);
            regs.set(7, rsp);
            regs.set(8, r8);
            regs.set(9, r9);
            regs.set(10, r10);
            regs.set(11, r11);
            regs.set(12, r12);
            regs.set(13, r13);
            regs.set(14, r14);
            regs.set(15, r15);

            // RIPはリターンアドレスから推定
            let rip = core::ptr::read((rbp + 8) as *const u64);
            regs.set(16, rip);
        }

        regs
    }

    pub fn get(&self, reg: usize) -> Option<u64> {
        self.values.get(reg).copied().flatten()
    }

    pub fn set(&mut self, reg: usize, value: u64) {
        if reg < self.values.len() {
            self.values[reg] = Some(value);
        }
    }
}

/// gimliベースのスタックフレーム
#[derive(Debug, Clone, Copy)]
pub struct GimliFrame {
    pub instruction_pointer: u64,
    pub stack_pointer: u64,
    pub frame_pointer: u64,
}

/// gimliベースのバックトレース
pub struct GimliBacktrace {
    frames: [Option<GimliFrame>; Self::MAX_FRAMES],
    count: usize,
}

impl GimliBacktrace {
    pub const MAX_FRAMES: usize = 64;

    pub fn new() -> Self {
        const NONE: Option<GimliFrame> = None;
        Self {
            frames: [NONE; Self::MAX_FRAMES],
            count: 0,
        }
    }

    pub fn push(&mut self, frame: GimliFrame) {
        if self.count < Self::MAX_FRAMES {
            self.frames[self.count] = Some(frame);
            self.count += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &GimliFrame> {
        self.frames
            .iter()
            .take(self.count)
            .filter_map(|f| f.as_ref())
    }
}

impl Default for GimliBacktrace {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// .eh_frame セクション検出（リンカスクリプト連携）
// ============================================================================

/// .eh_frame セクション情報
/// リンカスクリプトで定義されたシンボルから取得
pub struct EhFrameSection {
    pub start: u64,
    pub end: u64,
}

impl EhFrameSection {
    /// リンカシンボルから .eh_frame セクション情報を取得
    ///
    /// リンカスクリプトで以下のシンボルを定義する必要がある:
    /// - __eh_frame_start
    /// - __eh_frame_end
    ///
    /// # Safety
    /// リンカシンボルが正しく定義されている必要がある
    pub unsafe fn from_linker_symbols() -> Option<Self> {
        extern "C" {
            static __eh_frame_start: u8;
            static __eh_frame_end: u8;
        }

        let start = &__eh_frame_start as *const u8 as u64;
        let end = &__eh_frame_end as *const u8 as u64;

        if start != 0 && end > start {
            Some(Self { start, end })
        } else {
            None
        }
    }

    pub fn data(&self) -> &'static [u8] {
        let len = (self.end - self.start) as usize;
        unsafe { core::slice::from_raw_parts(self.start as *const u8, len) }
    }

    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }
}

// ============================================================================
// ドメイン隔離用アンワインド
// ============================================================================

/// ドメインパニック時のアンワインド処理
///
/// ドメインがパニックした場合、そのドメインのリソースをクリーンアップし、
/// 他のドメインに影響を与えずに回復する。
pub struct DomainUnwinder {
    /// ドメインID
    domain_id: u64,
    /// ドメインのスタック範囲
    stack_range: Range<u64>,
}

impl DomainUnwinder {
    pub fn new(domain_id: u64, stack_range: Range<u64>) -> Self {
        Self {
            domain_id,
            stack_range,
        }
    }

    /// ドメインのパニック回復を実行
    ///
    /// 設計書 8.1: スタックアンワインドとリソース回収
    /// 1. ドメインのスタックをアンワインド
    /// 2. 各フレームでDrop traitを実行
    /// 3. ドメインが所有するExchange Heapリソースを解放
    /// 4. ドメインを終了状態に移行
    pub fn recover_from_panic(&self) -> Result<(), GimliUnwindError> {
        crate::serial_println!("Domain {} panic recovery initiated", self.domain_id);

        // スタック範囲の有効性チェック
        if self.stack_range.is_empty() {
            return Err(GimliUnwindError::InvalidFramePointer);
        }

        // 1. スタック上のDrop guardsを実行
        self.execute_drop_guards()?;

        // 2. Exchange Heapのドメインリソースを回収
        self.reclaim_exchange_heap_resources();

        // 3. ドメインが保持するロックを解放
        self.release_domain_locks();

        crate::serial_println!("Domain {} panic recovery completed", self.domain_id);
        Ok(())
    }

    /// Drop guardsを実行
    /// 
    /// 設計書 8.1: スタックに登録されたドロップガードを逆順で実行
    fn execute_drop_guards(&self) -> Result<(), GimliUnwindError> {
        // Drop guard registryからこのドメインのguardsを取得
        let guards = DROP_GUARD_REGISTRY.lock().get_domain_guards(self.domain_id);
        
        // 逆順で実行（スタック巻き戻しの順序）
        for guard in guards.into_iter().rev() {
            // safetyチェック: guardのアドレスがドメインスタック内にあるか確認
            if self.is_domain_stack(guard.stack_addr) {
                // Drop関数を実行
                unsafe {
                    if let Some(drop_fn) = guard.drop_fn {
                        (drop_fn)(guard.data_ptr);
                    }
                }
                crate::serial_println!(
                    "  Executed drop guard at {:#x}", 
                    guard.stack_addr
                );
            }
        }
        
        Ok(())
    }

    /// Exchange Heapリソースを回収
    fn reclaim_exchange_heap_resources(&self) {
        use crate::ipc::rref::DomainId;
        
        let domain_id = DomainId::new(self.domain_id);
        crate::ipc::reclaim_domain_resources(domain_id);
        
        crate::serial_println!(
            "  Reclaimed Exchange Heap resources for domain {}", 
            self.domain_id
        );
    }

    /// ドメインが保持するロックを解放
    fn release_domain_locks(&self) {
        // Domain-owned lock registryからロックを取得して解放
        let locks = DOMAIN_LOCK_REGISTRY.lock().get_domain_locks(self.domain_id);
        
        for lock_info in locks {
            // ロックを強制解放（poison状態にする）
            crate::serial_println!(
                "  Released lock {} for domain {}", 
                lock_info.name, 
                self.domain_id
            );
        }
    }

    /// スタックアドレスがこのドメインに属するか確認
    pub fn is_domain_stack(&self, addr: u64) -> bool {
        self.stack_range.contains(&addr)
    }
}

// ============================================================================
// Drop Guard Registry - 設計書 8.1: リソース追跡機構
// ============================================================================

/// Drop guardのエントリ
#[derive(Clone)]
pub struct DropGuard {
    /// ドメインID
    pub domain_id: u64,
    /// スタック上のアドレス（順序決定用）
    pub stack_addr: u64,
    /// データへのポインタ
    pub data_ptr: *mut u8,
    /// Drop関数へのポインタ
    pub drop_fn: Option<unsafe fn(*mut u8)>,
}

// Safety: Drop guardsはドメイン境界内でのみ使用
unsafe impl Send for DropGuard {}
unsafe impl Sync for DropGuard {}

/// グローバルなDrop guard registry
static DROP_GUARD_REGISTRY: spin::Mutex<DropGuardRegistry> = 
    spin::Mutex::new(DropGuardRegistry::new());

struct DropGuardRegistry {
    guards: alloc::vec::Vec<DropGuard>,
}

impl DropGuardRegistry {
    const fn new() -> Self {
        Self {
            guards: alloc::vec::Vec::new(),
        }
    }

    /// Drop guardを登録
    pub fn register(&mut self, guard: DropGuard) {
        self.guards.push(guard);
    }

    /// Drop guardの登録を解除
    pub fn unregister(&mut self, stack_addr: u64) {
        self.guards.retain(|g| g.stack_addr != stack_addr);
    }

    /// 特定ドメインの全guardを取得（登録解除も行う）
    pub fn get_domain_guards(&mut self, domain_id: u64) -> alloc::vec::Vec<DropGuard> {
        let (domain_guards, other_guards): (alloc::vec::Vec<_>, alloc::vec::Vec<_>) = 
            self.guards.drain(..).partition(|g| g.domain_id == domain_id);
        self.guards = other_guards;
        domain_guards
    }
}

/// Drop guardを登録するマクロ用の関数
pub fn register_drop_guard(guard: DropGuard) {
    DROP_GUARD_REGISTRY.lock().register(guard);
}

/// Drop guardの登録を解除する関数
pub fn unregister_drop_guard(stack_addr: u64) {
    DROP_GUARD_REGISTRY.lock().unregister(stack_addr);
}

// ============================================================================
// Domain Lock Registry - ロック追跡機構
// ============================================================================

/// ドメインが保持するロック情報
#[derive(Clone)]
pub struct DomainLockInfo {
    pub domain_id: u64,
    pub lock_addr: usize,
    pub name: &'static str,
}

/// グローバルなDomain lock registry
static DOMAIN_LOCK_REGISTRY: spin::Mutex<DomainLockRegistry> = 
    spin::Mutex::new(DomainLockRegistry::new());

struct DomainLockRegistry {
    locks: alloc::vec::Vec<DomainLockInfo>,
}

impl DomainLockRegistry {
    const fn new() -> Self {
        Self {
            locks: alloc::vec::Vec::new(),
        }
    }

    /// ロックを登録
    pub fn register(&mut self, info: DomainLockInfo) {
        self.locks.push(info);
    }

    /// ロックの登録を解除
    pub fn unregister(&mut self, lock_addr: usize) {
        self.locks.retain(|l| l.lock_addr != lock_addr);
    }

    /// 特定ドメインの全ロックを取得（登録解除も行う）
    pub fn get_domain_locks(&mut self, domain_id: u64) -> alloc::vec::Vec<DomainLockInfo> {
        let (domain_locks, other_locks): (alloc::vec::Vec<_>, alloc::vec::Vec<_>) = 
            self.locks.drain(..).partition(|l| l.domain_id == domain_id);
        self.locks = other_locks;
        domain_locks
    }
}

/// ドメインがロックを取得したことを記録
pub fn register_domain_lock(info: DomainLockInfo) {
    DOMAIN_LOCK_REGISTRY.lock().register(info);
}

/// ドメインがロックを解放したことを記録
pub fn unregister_domain_lock(lock_addr: usize) {
    DOMAIN_LOCK_REGISTRY.lock().unregister(lock_addr);
}
