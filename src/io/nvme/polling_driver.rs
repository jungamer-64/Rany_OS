// ============================================================================
// src/io/nvme/polling_driver.rs - NVMe Polling Mode Driver
// ============================================================================
//!
//! # NVMeポーリングモードドライバ
//!
//! 設計書6.3に基づく高性能NVMeストレージアクセス。
//! コアごとのSubmission/Completion Queueとポーリングモードで
//! 最大スループットを実現。
//!
//! ## 機能
//! - マルチキューサポート（コアごとのSQ/CQ）
//! - ポーリングモード（割り込み不使用）
//! - 非同期コマンド発行
//! - CMB（Controller Memory Buffer）サポート

#![allow(dead_code)]

use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering};

use super::commands::{NvmeCommand, NvmeCompletion};
use super::controller::{
    CmbInfo, NvmeAdminQueueAttributes, NvmeCapabilities, NvmeControllerConfig,
    NvmeControllerStatus, CQ_ENTRY_SIZE, DEFAULT_QUEUE_DEPTH, MAX_QUEUE_DEPTH,
    MAX_TRANSFER_SIZE, POLL_BATCH_SIZE, QUEUE_ENTRY_SIZE, FEATURE_NUM_QUEUES,
};
use super::defs::AdminOpcode;
use super::per_core::PerCoreNvmeQueue;
use super::queue::QueuePair;

// ============================================================================
// Driver Statistics
// ============================================================================

/// ドライバ全体の統計
#[derive(Debug, Default)]
pub struct NvmeDriverStats {
    pub total_commands_submitted: u64,
    pub total_commands_completed: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub total_errors: u64,
    pub total_poll_cycles: u64,
}

// ============================================================================
// Polling Driver
// ============================================================================

/// NVMeポーリングドライバ
pub struct NvmePollingDriver {
    /// BAR0ベースアドレス
    bar0: u64,
    /// コントローラキャパシティ
    cap: NvmeCapabilities,
    /// ドアベルストライド（バイト単位）
    doorbell_stride: usize,
    /// 管理キュー
    admin_queue: Option<QueuePair>,
    /// コアごとのI/Oキュー
    io_queues: Vec<PerCoreNvmeQueue>,
    /// 名前空間ID
    pub nsid: u32,
    /// 最大転送サイズ
    max_transfer_size: usize,
    /// 最大キュー深度
    pub max_queue_depth: u16,
    /// アロケートされたI/Oキュー数
    allocated_sq_count: u16,
    allocated_cq_count: u16,
    /// アクティブフラグ
    active: AtomicBool,
    /// 割り込みモード（falseならポーリング）
    interrupt_mode: bool,
    /// Controller Memory Buffer情報
    cmb_info: Option<CmbInfo>,
    /// CMBを使用するかどうか
    use_cmb: bool,
    /// DMAコンテキスト（Admin/Identify バッファ用）
    dma_context: crate::io::dma::DeviceDmaContext,
    /// Admin SQバッファ（動的割り当て）
    admin_sq_buffer: Option<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>>,
    /// Admin CQバッファ（動的割り当て）
    admin_cq_buffer: Option<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>>,
    /// Identifyバッファ（動的割り当て）
    identify_buffer: Option<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>>,
}

impl NvmePollingDriver {
    /// 新しいドライバを作成
    pub fn new(bar0: u64, num_cores: u32) -> Self {
        let mut io_queues = Vec::new();
        for i in 0..num_cores {
            io_queues.push(PerCoreNvmeQueue::new(i));
        }

        Self {
            bar0,
            cap: NvmeCapabilities::new(0),
            doorbell_stride: 4, // デフォルト
            admin_queue: None,
            io_queues,
            nsid: 1,
            max_transfer_size: MAX_TRANSFER_SIZE,
            max_queue_depth: DEFAULT_QUEUE_DEPTH,
            allocated_sq_count: 0,
            allocated_cq_count: 0,
            active: AtomicBool::new(false),
            interrupt_mode: false, // ポーリングモード
            cmb_info: None,
            use_cmb: true, // デフォルトでCMBを使用（利用可能なら）
            dma_context: crate::io::dma::DeviceDmaContext::new(),
            admin_sq_buffer: None,
            admin_cq_buffer: None,
            identify_buffer: None,
        }
    }

    // ========================================================================
    // Register Access
    // ========================================================================

    /// レジスタを読む
    unsafe fn read_reg32(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.bar0 + offset as u64) as *const u32) }
    }

    /// レジスタを書く
    unsafe fn write_reg32(&self, offset: usize, value: u32) {
        unsafe { write_volatile((self.bar0 + offset as u64) as *mut u32, value) }
    }

    /// 64ビットレジスタを読む
    unsafe fn read_reg64(&self, offset: usize) -> u64 {
        unsafe { read_volatile((self.bar0 + offset as u64) as *const u64) }
    }

    /// 64ビットレジスタを書く
    unsafe fn write_reg64(&self, offset: usize, value: u64) {
        unsafe { write_volatile((self.bar0 + offset as u64) as *mut u64, value) }
    }

    /// コントローラステータスを取得
    fn get_status(&self) -> NvmeControllerStatus {
        unsafe { NvmeControllerStatus::new(self.read_reg32(0x1C)) }
    }

    /// ドアベルアドレスを計算
    fn doorbell_address(&self, qid: u16, is_sq: bool) -> *mut u32 {
        let offset =
            0x1000 + ((2 * qid as usize + if is_sq { 0 } else { 1 }) * self.doorbell_stride);
        (self.bar0 + offset as u64) as *mut u32
    }

    // ========================================================================
    // Controller Management
    // ========================================================================

    /// コントローラを無効化
    fn disable_controller(&self) -> Result<(), &'static str> {
        unsafe {
            let mut cc = NvmeControllerConfig::from_raw(self.read_reg32(0x14));
            cc.set_enable(false);
            self.write_reg32(0x14, cc.raw());

            for _ in 0..1000 {
                let status = self.get_status();
                if !status.rdy() {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err("Controller disable timeout")
    }

    /// コントローラを有効化
    fn enable_controller(&self) -> Result<(), &'static str> {
        unsafe {
            let mut cc = NvmeControllerConfig::new();
            cc.set_enable(true)
                .set_css(0) // NVM Command Set
                .set_mps(0) // 4KB pages
                .set_ams(0) // Round Robin
                .set_iosqes(6) // 64 bytes (2^6)
                .set_iocqes(4); // 16 bytes (2^4)

            self.write_reg32(0x14, cc.raw());

            let timeout = self.cap.to() as u64 * 500;
            for _ in 0..timeout {
                let status = self.get_status();
                if status.cfs() {
                    return Err("Controller fatal status");
                }
                if status.rdy() {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err("Controller enable timeout")
    }

    /// Admin Queueをセットアップ
    unsafe fn setup_admin_queue(
        &mut self,
        asq: u64,
        acq: u64,
        depth: u16,
    ) -> Result<(), &'static str> {
        let mut aqa = NvmeAdminQueueAttributes::new();
        aqa.set_asqs(depth - 1).set_acqs(depth - 1);
        unsafe { self.write_reg32(0x24, aqa.raw()) };
        unsafe { self.write_reg64(0x28, asq) };
        unsafe { self.write_reg64(0x30, acq) };
        Ok(())
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// コントローラを初期化
    pub fn init(&mut self) -> Result<(), &'static str> {
        // CAP レジスタを読む
        let cap_raw = unsafe { self.read_reg64(0x00) };
        self.cap = NvmeCapabilities::new(cap_raw);

        // ドアベルストライドを計算
        self.doorbell_stride = self.cap.doorbell_stride_bytes();
        self.max_queue_depth = self.cap.max_queue_depth().min(MAX_QUEUE_DEPTH);

        // CMB情報を取得
        if self.use_cmb {
            let cmbloc = unsafe { self.read_reg32(0x38) };
            let cmbsz = unsafe { self.read_reg32(0x3C) };
            let cmb_info = CmbInfo::from_registers(self.bar0, cmbloc, cmbsz, &self.cap);

            if cmb_info.supported {
                if cmb_info.base_addr != 0 {
                    let cmbmsc = unsafe { self.read_reg64(0x50) };
                    unsafe { self.write_reg64(0x50, cmbmsc | 1) };
                }
                self.cmb_info = Some(cmb_info);
            }
        }

        // コントローラを無効化
        self.disable_controller()?;

        // Admin Queueのセットアップ
        let admin_depth = DEFAULT_QUEUE_DEPTH.min(self.cap.max_queue_depth());
        self.init_admin_queue(admin_depth)?;

        // コントローラを有効化
        self.enable_controller()?;

        self.active.store(true, Ordering::Release);
        Ok(())
    }

    /// Admin Queueを初期化
    fn init_admin_queue(&mut self, depth: u16) -> Result<(), &'static str> {
        let sq_size = (depth as usize) * QUEUE_ENTRY_SIZE;
        let cq_size = (depth as usize) * CQ_ENTRY_SIZE;

        let asq_buffer = self
            .dma_context
            .create_slice(sq_size)
            .map_err(|_| "Failed to allocate ASQ DMA buffer")?;
        let acq_buffer = self
            .dma_context
            .create_slice(cq_size)
            .map_err(|_| "Failed to allocate ACQ DMA buffer")?;

        let asq_phys = asq_buffer.phys_addr().as_u64();
        let acq_phys = acq_buffer.phys_addr().as_u64();

        if asq_phys & 0xFFF != 0 || acq_phys & 0xFFF != 0 {
            return Err("DMA buffer not 4KB aligned");
        }

        unsafe {
            self.setup_admin_queue(asq_phys, acq_phys, depth)?;
        }

        let sq_doorbell = (self.bar0 + 0x1000) as *mut u32;
        let cq_doorbell = (self.bar0 + 0x1000 + self.doorbell_stride as u64) as *mut u32;

        let admin_qp = unsafe {
            QueuePair::new(
                asq_phys as *mut NvmeCommand,
                acq_phys as *mut NvmeCompletion,
                depth,
                sq_doorbell,
                cq_doorbell,
                0, // Admin Queue ID = 0
            )
        };

        self.admin_sq_buffer = Some(asq_buffer);
        self.admin_cq_buffer = Some(acq_buffer);
        self.admin_queue = Some(admin_qp);

        Ok(())
    }

    /// Identify Controllerコマンドを発行
    #[allow(dead_code)]
    fn identify_controller(&mut self) -> Result<(), &'static str> {
        let admin_queue = self.admin_queue.as_ref().ok_or("Admin queue not initialized")?;

        let identify_buffer = self
            .dma_context
            .create_slice(4096)
            .map_err(|_| "Failed to allocate Identify DMA buffer")?;
        let buffer_ptr = identify_buffer.phys_addr().as_u64();

        let mut cmd = NvmeCommand::default();
        cmd.set_opcode(AdminOpcode::Identify as u8);
        cmd.set_cid(0);
        cmd.nsid = 0;
        cmd.set_prp(buffer_ptr, 0);
        cmd.cdw10 = 1; // CNS = 1 (Identify Controller)

        admin_queue.submit(&cmd)?;

        for _ in 0..10000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                let status = cqe.status >> 1;
                if status != 0 {
                    return Err("Identify Controller command failed");
                }
                self.identify_buffer = Some(identify_buffer);
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err("Identify Controller timeout")
    }

    /// Set Features - Number of Queuesを設定
    #[allow(dead_code)]
    fn set_num_queues(&mut self, num_sq: u16, num_cq: u16) -> Result<(u16, u16), &'static str> {
        let admin_queue = self.admin_queue.as_ref().ok_or("Admin queue not initialized")?;

        let mut cmd = NvmeCommand::default();
        cmd.set_opcode(AdminOpcode::SetFeatures as u8);
        cmd.set_cid(1);
        cmd.cdw10 = FEATURE_NUM_QUEUES as u32;
        cmd.cdw11 = ((num_cq.saturating_sub(1) as u32) << 16) | (num_sq.saturating_sub(1) as u32);

        admin_queue.submit(&cmd)?;

        for _ in 0..10000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                let status = cqe.status >> 1;
                if status != 0 {
                    return Err("Set Features failed");
                }
                let allocated_sq = ((cqe.result & 0xFFFF) + 1) as u16;
                let allocated_cq = (((cqe.result >> 16) & 0xFFFF) + 1) as u16;
                return Ok((allocated_sq, allocated_cq));
            }
            core::hint::spin_loop();
        }

        Err("Set Features timeout")
    }

    // ========================================================================
    // CMB Support
    // ========================================================================

    /// CMBからSQバッファを割り当て（利用可能な場合）
    pub fn allocate_sq_from_cmb(&mut self, depth: u16) -> Option<u64> {
        self.cmb_info.as_mut().and_then(|cmb| cmb.allocate_sq(depth))
    }

    /// CMBからCQバッファを割り当て（利用可能な場合）
    pub fn allocate_cq_from_cmb(&mut self, depth: u16) -> Option<u64> {
        self.cmb_info.as_mut().and_then(|cmb| cmb.allocate_cq(depth))
    }

    /// CMBがサポートされているか
    pub fn has_cmb(&self) -> bool {
        self.cmb_info.as_ref().map_or(false, |cmb| cmb.supported)
    }

    /// CMB情報を取得
    pub fn cmb_info(&self) -> Option<&CmbInfo> {
        self.cmb_info.as_ref()
    }

    /// CMBを使用してI/Oキューを作成（高速版）
    pub fn create_io_queue_with_cmb(
        &mut self,
        core_id: u32,
        cq_buffer: *mut NvmeCompletion,
        cq_phys: u64,
        depth: u16,
    ) -> Result<(u16, Option<u64>), &'static str> {
        let cmb_sq_addr = self.allocate_sq_from_cmb(depth);

        if let Some(sq_addr) = cmb_sq_addr {
            let qid = self.create_io_queue_pair_internal(
                core_id,
                sq_addr as *mut NvmeCommand,
                cq_buffer,
                sq_addr,
                cq_phys,
                depth,
            )?;
            Ok((qid, Some(sq_addr)))
        } else {
            Err("CMB not available for SQ allocation")
        }
    }

    // ========================================================================
    // I/O Queue Management
    // ========================================================================

    /// 内部用：I/Oキューペアを作成
    fn create_io_queue_pair_internal(
        &mut self,
        core_id: u32,
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        sq_phys: u64,
        cq_phys: u64,
        depth: u16,
    ) -> Result<u16, &'static str> {
        let admin_queue = self.admin_queue.as_ref().ok_or("Admin queue not initialized")?;

        let qid = (core_id + 1) as u16;

        // Create I/O Completion Queue (cid=0 for first admin command of this queue)
        let create_cq_cmd = NvmeCommand::create_io_cq(0, qid, depth, cq_phys, 0, self.interrupt_mode);
        admin_queue.submit(&create_cq_cmd)?;
        self.poll_admin_completion()?;

        // Create I/O Submission Queue (cid=1 for second admin command of this queue)
        let create_sq_cmd = NvmeCommand::create_io_sq(1, qid, depth, sq_phys, qid, 0);
        admin_queue.submit(&create_sq_cmd)?;
        self.poll_admin_completion()?;

        // キューペアを設定
        let qp = unsafe {
            QueuePair::new(
                sq_buffer,
                cq_buffer,
                depth,
                self.doorbell_address(qid, true),
                self.doorbell_address(qid, false),
                qid,
            )
        };

        if let Some(queue) = self.io_queues.get(core_id as usize) {
            unsafe { queue.set_queue_pair(qp) };
        }

        self.allocated_sq_count += 1;
        self.allocated_cq_count += 1;

        Ok(qid)
    }

    /// I/Oキューペアを作成（公開API）
    pub fn create_io_queue_pair(
        &mut self,
        core_id: u32,
        sq_buffer: *mut NvmeCommand,
        cq_buffer: *mut NvmeCompletion,
        sq_phys: u64,
        cq_phys: u64,
        depth: u16,
    ) -> Result<u16, &'static str> {
        self.create_io_queue_pair_internal(core_id, sq_buffer, cq_buffer, sq_phys, cq_phys, depth)
    }

    /// Admin完了をポーリング
    fn poll_admin_completion(&self) -> Result<NvmeCompletion, &'static str> {
        let admin_queue = self.admin_queue.as_ref().ok_or("Admin queue not initialized")?;

        for _ in 0..100000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                if cqe.is_success() {
                    return Ok(cqe);
                } else {
                    return Err("Admin command failed");
                }
            }
            cpu_pause();
        }
        Err("Admin command timeout")
    }

    /// I/Oキューを設定（レガシーAPI）
    ///
    /// # Safety
    /// 初期化中にのみ呼び出すこと。
    pub unsafe fn setup_io_queue(&self, core_id: u32, qp: QueuePair) {
        if let Some(queue) = self.io_queues.get(core_id as usize) {
            unsafe { queue.set_queue_pair(qp) };
        }
    }

    /// コアのキューを取得
    pub fn get_queue(&self, core_id: u32) -> Option<&PerCoreNvmeQueue> {
        self.io_queues.get(core_id as usize)
    }

    // ========================================================================
    // Polling
    // ========================================================================

    /// ポーリングループを実行（最適化版）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_loop(&self, core_id: u32) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let mut completed = 0;

        for _ in 0..POLL_BATCH_SIZE {
            if let Some(_cqe) = unsafe { queue.poll() } {
                completed += 1;
            } else {
                break;
            }
        }

        if completed == 0 {
            cpu_pause();
        }

        completed
    }

    /// バッチポーリング（高スループット用）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_batch(&self, core_id: u32, completions: &mut [NvmeCompletion]) -> usize {
        let queue = match self.get_queue(core_id) {
            Some(q) => q,
            None => return 0,
        };

        let mut count = 0;
        for slot in completions.iter_mut() {
            if let Some(cqe) = unsafe { queue.poll() } {
                *slot = cqe;
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    /// アダプティブポーリング（負荷に応じて調整）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn adaptive_poll(&self, core_id: u32, idle_count: &mut u32) -> usize {
        let completed = unsafe { self.poll_loop(core_id) };

        if completed > 0 {
            *idle_count = 0;
        } else {
            *idle_count += 1;
            if *idle_count > 100 {
                for _ in 0..10 {
                    cpu_pause();
                }
            }
        }

        completed
    }

    // ========================================================================
    // Status & Statistics
    // ========================================================================

    /// アクティブかどうか
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// 最大転送サイズを取得
    pub fn max_transfer_size(&self) -> usize {
        self.max_transfer_size
    }

    /// 統計を収集
    pub fn collect_stats(&self) -> NvmeDriverStats {
        let mut stats = NvmeDriverStats::default();

        for queue in &self.io_queues {
            let qs = queue.stats();
            stats.total_commands_submitted += qs.commands_submitted.load(Ordering::Relaxed);
            stats.total_commands_completed += qs.commands_completed.load(Ordering::Relaxed);
            stats.total_read_bytes += qs.read_bytes.load(Ordering::Relaxed);
            stats.total_write_bytes += qs.write_bytes.load(Ordering::Relaxed);
            stats.total_errors += qs.errors.load(Ordering::Relaxed);
            stats.total_poll_cycles += qs.poll_cycles.load(Ordering::Relaxed);
        }

        stats
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// CPU PAUSE命令（スピン待機の電力効率化）
#[inline(always)]
fn cpu_pause() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_pause();
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        core::hint::spin_loop();
    }
}
