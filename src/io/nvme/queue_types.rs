// ============================================================================
// src/io/nvme/queue_types.rs - NVMe Queue Type Separation
// ============================================================================
//!
//! # NVMe Queue Type Separation
//!
//! Admin Queue と I/O Queue を型レベルで分離。
//! 型状態パターンを使用して、誤った Queue の使用をコンパイル時に防止。
//!
//! ## 設計方針
//! - Admin Queue: コントローラ管理コマンド専用
//! - I/O Queue: データ転送コマンド専用
//! - 型パラメータでキュータイプを表現
//! - Phantom Type による型安全性

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use super::commands::{NvmeCommand, NvmeCompletion};
use super::defs::{AdminOpcode, IoOpcode, SQE_SIZE, CQE_SIZE};

// ============================================================================
// Queue Type Markers
// ============================================================================

/// Admin Queue マーカー
pub struct AdminQueue;

/// I/O Queue マーカー
pub struct IoQueue;

/// Queue Type Trait
pub trait QueueType: Send + Sync {
    /// キュータイプ名
    const NAME: &'static str;
    /// 最大キュー深度
    const MAX_DEPTH: u16;
    /// デフォルトキュー深度
    const DEFAULT_DEPTH: u16;
}

impl QueueType for AdminQueue {
    const NAME: &'static str = "Admin";
    const MAX_DEPTH: u16 = 4096;
    const DEFAULT_DEPTH: u16 = 32;
}

impl QueueType for IoQueue {
    const NAME: &'static str = "I/O";
    const MAX_DEPTH: u16 = 65535;
    const DEFAULT_DEPTH: u16 = 1024;
}

// ============================================================================
// Admin Command Trait
// ============================================================================

/// Admin コマンドトレイト
pub trait AdminCommandTrait {
    /// オペコードを取得
    fn admin_opcode(&self) -> AdminOpcode;
    /// NvmeCommand に変換
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand;
}

/// I/O コマンドトレイト
pub trait IoCommandTrait {
    /// オペコードを取得
    fn io_opcode(&self) -> IoOpcode;
    /// NvmeCommand に変換
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand;
}

// ============================================================================
// Admin Commands
// ============================================================================

/// Identify コマンド
pub struct IdentifyCommand {
    /// Controller or Namespace (CNS)
    pub cns: u8,
    /// PRP1 (データバッファアドレス)
    pub prp1: u64,
}

impl AdminCommandTrait for IdentifyCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::Identify
    }
    
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::Identify as u8, cid);
        cmd.nsid = nsid;
        cmd.dptr1 = self.prp1;
        cmd.cdw10 = self.cns as u32;
        cmd
    }
}

/// Create I/O Completion Queue コマンド
pub struct CreateIoCqCommand {
    /// Queue ID
    pub qid: u16,
    /// Queue Size (0-based)
    pub qsize: u16,
    /// PRP1 (CQ buffer address)
    pub prp1: u64,
    /// Interrupt Vector
    pub iv: u16,
    /// Interrupts Enabled
    pub ien: bool,
    /// Physically Contiguous
    pub pc: bool,
}

impl AdminCommandTrait for CreateIoCqCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::CreateIOCQ
    }
    
    fn to_nvme_command(&self, cid: u16, _nsid: u32) -> NvmeCommand {
        let cdw10 = (self.qid as u32) | ((self.qsize as u32) << 16);
        let cdw11 = (self.iv as u32) 
            | if self.ien { 1 << 1 } else { 0 }
            | if self.pc { 1 } else { 0 };
        
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::CreateIOCQ as u8, cid);
        cmd.dptr1 = self.prp1;
        cmd.cdw10 = cdw10;
        cmd.cdw11 = cdw11;
        cmd
    }
}

/// Create I/O Submission Queue コマンド
pub struct CreateIoSqCommand {
    /// Queue ID
    pub qid: u16,
    /// Queue Size (0-based)
    pub qsize: u16,
    /// PRP1 (SQ buffer address)
    pub prp1: u64,
    /// Associated CQ ID
    pub cqid: u16,
    /// Queue Priority
    pub qprio: u8,
    /// Physically Contiguous
    pub pc: bool,
}

impl AdminCommandTrait for CreateIoSqCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::CreateIOSQ
    }
    
    fn to_nvme_command(&self, cid: u16, _nsid: u32) -> NvmeCommand {
        let cdw10 = (self.qid as u32) | ((self.qsize as u32) << 16);
        let cdw11 = (self.cqid as u32) 
            | ((self.qprio as u32) << 1)
            | if self.pc { 1 } else { 0 };
        
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::CreateIOSQ as u8, cid);
        cmd.dptr1 = self.prp1;
        cmd.cdw10 = cdw10;
        cmd.cdw11 = cdw11;
        cmd
    }
}

/// Delete I/O Submission Queue コマンド
pub struct DeleteIoSqCommand {
    pub qid: u16,
}

impl AdminCommandTrait for DeleteIoSqCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::DeleteIOSQ
    }
    
    fn to_nvme_command(&self, cid: u16, _nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::DeleteIOSQ as u8, cid);
        cmd.cdw10 = self.qid as u32;
        cmd
    }
}

/// Delete I/O Completion Queue コマンド
pub struct DeleteIoCqCommand {
    pub qid: u16,
}

impl AdminCommandTrait for DeleteIoCqCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::DeleteIOCQ
    }
    
    fn to_nvme_command(&self, cid: u16, _nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::DeleteIOCQ as u8, cid);
        cmd.cdw10 = self.qid as u32;
        cmd
    }
}

/// Set Features コマンド
pub struct SetFeaturesCommand {
    pub fid: u8,
    pub cdw11: u32,
}

impl AdminCommandTrait for SetFeaturesCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::SetFeatures
    }
    
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::SetFeatures as u8, cid);
        cmd.nsid = nsid;
        cmd.cdw10 = self.fid as u32;
        cmd.cdw11 = self.cdw11;
        cmd
    }
}

/// Get Features コマンド
pub struct GetFeaturesCommand {
    pub fid: u8,
    pub sel: u8,
}

impl AdminCommandTrait for GetFeaturesCommand {
    fn admin_opcode(&self) -> AdminOpcode {
        AdminOpcode::GetFeatures
    }
    
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(AdminOpcode::GetFeatures as u8, cid);
        cmd.nsid = nsid;
        cmd.cdw10 = (self.fid as u32) | ((self.sel as u32) << 8);
        cmd
    }
}

// ============================================================================
// I/O Commands
// ============================================================================

/// Read コマンド
pub struct ReadCommand {
    /// Starting LBA
    pub slba: u64,
    /// Number of Logical Blocks (0-based)
    pub nlb: u16,
    /// PRP Entry 1
    pub prp1: u64,
    /// PRP Entry 2 / PRP List
    pub prp2: u64,
}

impl IoCommandTrait for ReadCommand {
    fn io_opcode(&self) -> IoOpcode {
        IoOpcode::Read
    }
    
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(IoOpcode::Read as u8, cid);
        cmd.nsid = nsid;
        cmd.dptr1 = self.prp1;
        cmd.dptr2 = self.prp2;
        cmd.cdw10 = (self.slba & 0xFFFFFFFF) as u32;
        cmd.cdw11 = ((self.slba >> 32) & 0xFFFFFFFF) as u32;
        cmd.cdw12 = self.nlb as u32;
        cmd
    }
}

/// Write コマンド
pub struct WriteCommand {
    /// Starting LBA
    pub slba: u64,
    /// Number of Logical Blocks (0-based)
    pub nlb: u16,
    /// PRP Entry 1
    pub prp1: u64,
    /// PRP Entry 2 / PRP List
    pub prp2: u64,
}

impl IoCommandTrait for WriteCommand {
    fn io_opcode(&self) -> IoOpcode {
        IoOpcode::Write
    }
    
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(IoOpcode::Write as u8, cid);
        cmd.nsid = nsid;
        cmd.dptr1 = self.prp1;
        cmd.dptr2 = self.prp2;
        cmd.cdw10 = (self.slba & 0xFFFFFFFF) as u32;
        cmd.cdw11 = ((self.slba >> 32) & 0xFFFFFFFF) as u32;
        cmd.cdw12 = self.nlb as u32;
        cmd
    }
}

/// Flush コマンド
pub struct FlushCommand;

impl IoCommandTrait for FlushCommand {
    fn io_opcode(&self) -> IoOpcode {
        IoOpcode::Flush
    }
    
    fn to_nvme_command(&self, cid: u16, nsid: u32) -> NvmeCommand {
        let mut cmd = NvmeCommand::with_opcode_and_cid(IoOpcode::Flush as u8, cid);
        cmd.nsid = nsid;
        cmd
    }
}

// ============================================================================
// Typed Submission Queue
// ============================================================================

/// 型付きSubmission Queue
pub struct TypedSubmissionQueue<T: QueueType> {
    /// キューバッファ
    buffer: Box<[NvmeCommand]>,
    /// Tail (次の書き込み位置)
    tail: AtomicU16,
    /// キュー深度
    depth: u16,
    /// キューID
    qid: u16,
    /// 型マーカー
    _marker: PhantomData<T>,
}

impl<T: QueueType> TypedSubmissionQueue<T> {
    /// 新しいSubmission Queueを作成
    pub fn new(qid: u16, depth: u16) -> Self {
        let depth = depth.min(T::MAX_DEPTH);
        let buffer = vec![NvmeCommand::new(); depth as usize].into_boxed_slice();
        
        Self {
            buffer,
            tail: AtomicU16::new(0),
            depth,
            qid,
            _marker: PhantomData,
        }
    }
    
    /// コマンドをキューに追加
    pub fn submit(&self, cmd: NvmeCommand) -> Option<u16> {
        let tail = self.tail.load(Ordering::Acquire);
        let next_tail = (tail + 1) % self.depth;
        
        // コマンドを書き込み
        unsafe {
            let ptr = self.buffer.as_ptr() as *mut NvmeCommand;
            ptr::write_volatile(ptr.add(tail as usize), cmd);
        }
        
        self.tail.store(next_tail, Ordering::Release);
        Some(tail)
    }
    
    /// 現在のTail位置を取得
    pub fn tail(&self) -> u16 {
        self.tail.load(Ordering::Acquire)
    }
    
    /// バッファアドレスを取得
    pub fn buffer_addr(&self) -> u64 {
        self.buffer.as_ptr() as u64
    }
    
    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }
    
    /// キュー深度を取得
    pub fn depth(&self) -> u16 {
        self.depth
    }
}

// ============================================================================
// Typed Completion Queue
// ============================================================================

/// 型付きCompletion Queue
pub struct TypedCompletionQueue<T: QueueType> {
    /// キューバッファ
    buffer: Box<[NvmeCompletion]>,
    /// Head (次の読み取り位置)
    head: AtomicU16,
    /// 現在のフェーズビット
    phase: AtomicU16,
    /// キュー深度
    depth: u16,
    /// キューID
    qid: u16,
    /// 型マーカー
    _marker: PhantomData<T>,
}

impl<T: QueueType> TypedCompletionQueue<T> {
    /// 新しいCompletion Queueを作成
    pub fn new(qid: u16, depth: u16) -> Self {
        let depth = depth.min(T::MAX_DEPTH);
        let buffer = vec![NvmeCompletion::default(); depth as usize].into_boxed_slice();
        
        Self {
            buffer,
            head: AtomicU16::new(0),
            phase: AtomicU16::new(1),
            depth,
            qid,
            _marker: PhantomData,
        }
    }
    
    /// 完了エントリをポーリング
    pub fn poll(&self) -> Option<NvmeCompletion> {
        let head = self.head.load(Ordering::Acquire);
        let phase = self.phase.load(Ordering::Acquire);
        
        // 完了エントリを読み取り
        let cqe = unsafe {
            let ptr = self.buffer.as_ptr().add(head as usize);
            ptr::read_volatile(ptr)
        };
        
        // フェーズビットを確認
        let cqe_phase = (cqe.status >> 0) & 1;
        if cqe_phase != phase {
            return None;
        }
        
        // Headを進める
        let next_head = (head + 1) % self.depth;
        if next_head == 0 {
            // ラップアラウンド時にフェーズを反転
            self.phase.store(1 - phase, Ordering::Release);
        }
        self.head.store(next_head, Ordering::Release);
        
        Some(cqe)
    }
    
    /// 複数の完了エントリをポーリング
    pub fn poll_batch(&self, max: usize) -> Vec<NvmeCompletion> {
        let mut completions = Vec::with_capacity(max);
        
        for _ in 0..max {
            match self.poll() {
                Some(cqe) => completions.push(cqe),
                None => break,
            }
        }
        
        completions
    }
    
    /// 現在のHead位置を取得
    pub fn head(&self) -> u16 {
        self.head.load(Ordering::Acquire)
    }
    
    /// バッファアドレスを取得
    pub fn buffer_addr(&self) -> u64 {
        self.buffer.as_ptr() as u64
    }
    
    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.qid
    }
    
    /// キュー深度を取得
    pub fn depth(&self) -> u16 {
        self.depth
    }
}

// ============================================================================
// Typed Queue Pair
// ============================================================================

/// 型付きQueue Pair
pub struct TypedQueuePair<T: QueueType> {
    /// Submission Queue
    pub sq: TypedSubmissionQueue<T>,
    /// Completion Queue
    pub cq: TypedCompletionQueue<T>,
    /// コマンドID生成器
    cid_counter: AtomicU16,
}

impl<T: QueueType> TypedQueuePair<T> {
    /// 新しいQueue Pairを作成
    pub fn new(qid: u16, depth: u16) -> Self {
        Self {
            sq: TypedSubmissionQueue::new(qid, depth),
            cq: TypedCompletionQueue::new(qid, depth),
            cid_counter: AtomicU16::new(0),
        }
    }
    
    /// 次のコマンドIDを取得
    pub fn next_cid(&self) -> u16 {
        self.cid_counter.fetch_add(1, Ordering::Relaxed)
    }
    
    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.sq.qid()
    }
}

// ============================================================================
// Admin Queue Pair
// ============================================================================

/// Admin Queue Pair (キューID=0固定)
pub struct AdminQueuePair {
    inner: TypedQueuePair<AdminQueue>,
}

impl AdminQueuePair {
    /// 新しいAdmin Queue Pairを作成
    pub fn new(depth: u16) -> Self {
        Self {
            inner: TypedQueuePair::new(0, depth),
        }
    }
    
    /// Adminコマンドを発行
    pub fn submit_admin<C: AdminCommandTrait>(&self, cmd: &C, nsid: u32) -> u16 {
        let cid = self.inner.next_cid();
        let nvme_cmd = cmd.to_nvme_command(cid, nsid);
        self.inner.sq.submit(nvme_cmd);
        cid
    }
    
    /// 完了をポーリング
    pub fn poll(&self) -> Option<NvmeCompletion> {
        self.inner.cq.poll()
    }
    
    /// SQバッファアドレスを取得
    pub fn sq_addr(&self) -> u64 {
        self.inner.sq.buffer_addr()
    }
    
    /// CQバッファアドレスを取得
    pub fn cq_addr(&self) -> u64 {
        self.inner.cq.buffer_addr()
    }
    
    /// SQ Tailを取得
    pub fn sq_tail(&self) -> u16 {
        self.inner.sq.tail()
    }
    
    /// CQ Headを取得
    pub fn cq_head(&self) -> u16 {
        self.inner.cq.head()
    }
}

// ============================================================================
// I/O Queue Pair
// ============================================================================

/// I/O Queue Pair
pub struct IoQueuePair {
    inner: TypedQueuePair<IoQueue>,
}

impl IoQueuePair {
    /// 新しいI/O Queue Pairを作成
    pub fn new(qid: u16, depth: u16) -> Self {
        Self {
            inner: TypedQueuePair::new(qid, depth),
        }
    }
    
    /// I/Oコマンドを発行
    pub fn submit_io<C: IoCommandTrait>(&self, cmd: &C, nsid: u32) -> u16 {
        let cid = self.inner.next_cid();
        let nvme_cmd = cmd.to_nvme_command(cid, nsid);
        self.inner.sq.submit(nvme_cmd);
        cid
    }
    
    /// 完了をポーリング
    pub fn poll(&self) -> Option<NvmeCompletion> {
        self.inner.cq.poll()
    }
    
    /// 複数の完了をポーリング
    pub fn poll_batch(&self, max: usize) -> Vec<NvmeCompletion> {
        self.inner.cq.poll_batch(max)
    }
    
    /// キューIDを取得
    pub fn qid(&self) -> u16 {
        self.inner.qid()
    }
    
    /// SQバッファアドレスを取得
    pub fn sq_addr(&self) -> u64 {
        self.inner.sq.buffer_addr()
    }
    
    /// CQバッファアドレスを取得
    pub fn cq_addr(&self) -> u64 {
        self.inner.cq.buffer_addr()
    }
    
    /// SQ Tailを取得
    pub fn sq_tail(&self) -> u16 {
        self.inner.sq.tail()
    }
    
    /// CQ Headを取得
    pub fn cq_head(&self) -> u16 {
        self.inner.cq.head()
    }
}

// ============================================================================
// Queue Manager
// ============================================================================

/// NVMe Queue Manager
pub struct NvmeQueueManager {
    /// Admin Queue
    admin: AdminQueuePair,
    /// I/O Queues
    io_queues: Vec<IoQueuePair>,
    /// 最大I/Oキュー数
    max_io_queues: u16,
}

impl NvmeQueueManager {
    /// 新しいQueue Managerを作成
    pub fn new(admin_depth: u16) -> Self {
        Self {
            admin: AdminQueuePair::new(admin_depth),
            io_queues: Vec::new(),
            max_io_queues: 0,
        }
    }
    
    /// Admin Queueを取得
    pub fn admin(&self) -> &AdminQueuePair {
        &self.admin
    }
    
    /// I/O Queueを作成
    pub fn create_io_queue(&mut self, depth: u16) -> Option<u16> {
        let qid = (self.io_queues.len() + 1) as u16;
        
        if qid > self.max_io_queues && self.max_io_queues > 0 {
            return None;
        }
        
        self.io_queues.push(IoQueuePair::new(qid, depth));
        Some(qid)
    }
    
    /// I/O Queueを取得
    pub fn io_queue(&self, qid: u16) -> Option<&IoQueuePair> {
        if qid == 0 || qid as usize > self.io_queues.len() {
            return None;
        }
        Some(&self.io_queues[qid as usize - 1])
    }
    
    /// 最大I/Oキュー数を設定
    pub fn set_max_io_queues(&mut self, max: u16) {
        self.max_io_queues = max;
    }
    
    /// I/Oキュー数を取得
    pub fn io_queue_count(&self) -> usize {
        self.io_queues.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_type_traits() {
        assert_eq!(AdminQueue::NAME, "Admin");
        assert_eq!(IoQueue::NAME, "I/O");
        assert_eq!(AdminQueue::MAX_DEPTH, 4096);
        assert_eq!(IoQueue::MAX_DEPTH, 65535);
    }

    #[test]
    fn test_identify_command() {
        let cmd = IdentifyCommand { cns: 1, prp1: 0x1000 };
        let nvme_cmd = cmd.to_nvme_command(42, 0);
        assert_eq!(nvme_cmd.opcode(), AdminOpcode::Identify as u8);
        assert_eq!(nvme_cmd.cid(), 42);
        assert_eq!(nvme_cmd.cdw10, 1);
    }

    #[test]
    fn test_read_command() {
        let cmd = ReadCommand {
            slba: 0x12345678,
            nlb: 7,
            prp1: 0x2000,
            prp2: 0,
        };
        let nvme_cmd = cmd.to_nvme_command(100, 1);
        assert_eq!(nvme_cmd.opcode(), IoOpcode::Read as u8);
        assert_eq!(nvme_cmd.nsid, 1);
    }
}
