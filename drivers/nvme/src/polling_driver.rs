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
use core::sync::atomic::{AtomicBool, Ordering};
use hal::mmio;
use kernel_api::DmaBuffer;

use super::commands::{NvmeCommand, NvmeCompletion};
use super::controller::{
    CQ_ENTRY_SIZE, CmbInfo, DEFAULT_QUEUE_DEPTH, FEATURE_NUM_QUEUES, MAX_QUEUE_DEPTH,
    MAX_SGL_ENTRIES, MAX_TRANSFER_SIZE, NvmeAdminQueueAttributes, NvmeCapabilities,
    NvmeControllerConfig, NvmeControllerStatus, QUEUE_ENTRY_SIZE,
};
use super::defs::{AdminOpcode, SglDescriptor};
use super::identify::{IdentifyController, IdentifyNamespace};
use super::per_core::PerCoreNvmeQueue;
use super::queue::QueuePair;

// Identify Controller SGLS bits (NVMe spec).
const SGLS_SUPPORTED: u32 = 1 << 0;
const SGLS_DATA_BLOCK: u32 = 1 << 2;

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
    /// 初期化済みI/Oキュー数
    io_queue_count: u16,
    /// コアごとのI/O SQ DMAバッファ
    io_sq_buffers: Vec<Option<DmaBuffer>>,
    /// コアごとのI/O CQ DMAバッファ
    io_cq_buffers: Vec<Option<DmaBuffer>>,
    /// 名前空間ID
    pub nsid: u32,
    /// 最大転送サイズ
    max_transfer_size: usize,
    /// 最大キュー深度
    pub max_queue_depth: u16,
    /// 名前空間の論理ブロックサイズ（バイト）
    namespace_block_size: u32,
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
    /// Admin SQバッファ（動的割り当て）
    admin_sq_buffer: Option<DmaBuffer>,
    /// Admin CQバッファ（動的割り当て）
    admin_cq_buffer: Option<DmaBuffer>,
    /// Identifyバッファ（動的割り当て）
    identify_buffer: Option<DmaBuffer>,
    /// Identify Controllerデータ
    identify_controller: Option<IdentifyController>,
}

impl NvmePollingDriver {
    /// 新しいドライバを作成
    pub fn new(bar0: u64, num_cores: u32) -> Self {
        let mut io_queues = Vec::new();
        let mut io_sq_buffers = Vec::new();
        let mut io_cq_buffers = Vec::new();
        for i in 0..num_cores {
            io_queues.push(PerCoreNvmeQueue::new(i));
            io_sq_buffers.push(None);
            io_cq_buffers.push(None);
        }

        Self {
            bar0,
            cap: NvmeCapabilities::new(0),
            doorbell_stride: 4, // デフォルト
            admin_queue: None,
            io_queues,
            io_queue_count: 0,
            io_sq_buffers,
            io_cq_buffers,
            nsid: 1,
            max_transfer_size: MAX_TRANSFER_SIZE,
            max_queue_depth: DEFAULT_QUEUE_DEPTH,
            namespace_block_size: 512,
            allocated_sq_count: 0,
            allocated_cq_count: 0,
            active: AtomicBool::new(false),
            interrupt_mode: false, // ポーリングモードをデフォルトにする
            cmb_info: None,
            use_cmb: true, // デフォルトでCMBを使用（利用可能なら）
            admin_sq_buffer: None,
            admin_cq_buffer: None,
            identify_buffer: None,
            identify_controller: None,
        }
    }

    // ========================================================================
    // Register Access
    // ========================================================================

    /// レジスタを読む
    fn read_reg32(&self, offset: usize) -> u32 {
        mmio::mmio_read_u32((self.bar0 + offset as u64) as usize)
    }

    /// レジスタを書く
    fn write_reg32(&self, offset: usize, value: u32) {
        mmio::mmio_write_u32((self.bar0 + offset as u64) as usize, value)
    }

    /// 64ビットレジスタを読む
    fn read_reg64(&self, offset: usize) -> u64 {
        mmio::mmio_read_u64((self.bar0 + offset as u64) as usize)
    }

    /// 64ビットレジスタを書く
    fn write_reg64(&self, offset: usize, value: u64) {
        mmio::mmio_write_u64((self.bar0 + offset as u64) as usize, value)
    }

    /// コントローラステータスを取得
    fn get_status(&self) -> NvmeControllerStatus {
        NvmeControllerStatus::new(self.read_reg32(0x1C))
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
        Err("Controller disable timeout")
    }

    /// コントローラを有効化
    fn enable_controller(&self) -> Result<(), &'static str> {
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
        self.write_reg32(0x24, aqa.raw());
        self.write_reg64(0x28, asq);
        self.write_reg64(0x30, acq);
        Ok(())
    }

    // ========================================================================
    // Initialization
    // ========================================================================

    /// コントローラを初期化
    pub fn init(&mut self) -> Result<(), &'static str> {
        // CAP レジスタを読む
        let cap_raw = self.read_reg64(0x00);
        self.cap = NvmeCapabilities::new(cap_raw);

        // ドアベルストライドを計算
        self.doorbell_stride = self.cap.doorbell_stride_bytes();
        self.max_queue_depth = self.cap.max_queue_depth().min(MAX_QUEUE_DEPTH as u32) as u16;

        // CMB情報を取得
        if self.use_cmb {
            let cmbloc = self.read_reg32(0x38);
            let cmbsz = self.read_reg32(0x3C);
            let cmb_info = CmbInfo::from_registers(self.bar0, cmbloc, cmbsz, &self.cap);

            if cmb_info.supported {
                if cmb_info.base_addr != 0 {
                    let cmbmsc = self.read_reg64(0x50);
                    self.write_reg64(0x50, cmbmsc | 1);
                }
                self.cmb_info = Some(cmb_info);
            }
        }

        // コントローラを無効化
        self.disable_controller()?;

        // Admin Queueのセットアップ
        let admin_depth = (DEFAULT_QUEUE_DEPTH as u32).min(self.cap.max_queue_depth()) as u16;
        self.init_admin_queue(admin_depth)?;

        // コントローラを有効化
        self.enable_controller()?;

        if let Err(err) = self.identify_controller() {
            log::warn!("[NVME] Identify Controller failed: {}", err);
        }

        // Identify Namespaceでブロックサイズを取得
        if let Ok(ns) = self.identify_namespace(self.nsid) {
            let block_size = ns.block_size() as u32;
            if block_size != 0 {
                self.namespace_block_size = block_size;
            }
        }

        // I/Oキューを初期化
        let num_cores = self.io_queues.len() as u32;
        self.init_io_queues(num_cores)?;

        self.active.store(true, Ordering::Release);

        Ok(())
    }

    /// I/Oキューを初期化
    fn init_io_queues(&mut self, num_cores: u32) -> Result<(), &'static str> {
        if num_cores == 0 {
            return Err("No cores available for I/O queues");
        }

        // コントローラに対してI/Oキュー数を要求
        let (allocated_sq, allocated_cq) =
            self.set_num_queues(num_cores as u16, num_cores as u16).unwrap_or((1, 1));
        let io_queue_count = core::cmp::min(allocated_sq, allocated_cq).min(num_cores as u16);
        if io_queue_count == 0 {
            return Err("No I/O queues allocated by controller");
        }

        let depth = self
            .max_queue_depth
            .min(DEFAULT_QUEUE_DEPTH as u16)
            .max(2);
        let kernel = kernel_api::services::kernel();

        for core_id in 0..io_queue_count as u32 {
            let sq_size = (depth as usize) * QUEUE_ENTRY_SIZE;
            let cq_size = (depth as usize) * CQ_ENTRY_SIZE;

            // CQバッファはホストメモリから確保
            let cq_buffer = kernel
                .alloc_dma(cq_size)
                .map_err(|_| "Failed to allocate IO CQ DMA buffer")?;
            let cq_phys = cq_buffer.physical_address();
            if cq_phys & 0xFFF != 0 {
                return Err("IO CQ DMA buffer not 4KB aligned");
            }
            let cq_ptr = cq_buffer.as_ptr() as *mut NvmeCompletion;

            // SQはCMB優先（利用不可ならホストメモリ）
            if self.use_cmb && self.has_cmb() {
                if let Ok((_qid, _sq_addr)) =
                    self.create_io_queue_with_cmb(core_id, cq_ptr, cq_phys, depth)
                {
                    self.io_cq_buffers[core_id as usize] = Some(cq_buffer);
                    continue;
                }
            }

            let sq_buffer = kernel
                .alloc_dma(sq_size)
                .map_err(|_| "Failed to allocate IO SQ DMA buffer")?;
            let sq_phys = sq_buffer.physical_address();
            if sq_phys & 0xFFF != 0 {
                return Err("IO SQ DMA buffer not 4KB aligned");
            }
            let sq_ptr = sq_buffer.as_ptr() as *mut NvmeCommand;

            self.create_io_queue_pair_internal(
                core_id,
                sq_ptr,
                cq_ptr,
                sq_phys,
                cq_phys,
                depth,
            )?;

            self.io_sq_buffers[core_id as usize] = Some(sq_buffer);
            self.io_cq_buffers[core_id as usize] = Some(cq_buffer);
        }

        self.io_queue_count = self.allocated_sq_count;

        Ok(())
    }

    /// Admin Queueを初期化
    fn init_admin_queue(&mut self, depth: u16) -> Result<(), &'static str> {
        let sq_size = (depth as usize) * QUEUE_ENTRY_SIZE;
        let cq_size = (depth as usize) * CQ_ENTRY_SIZE;

        let kernel = kernel_api::services::kernel();

        // Alloc DMA via KernelServices
        let asq_buffer = kernel
            .alloc_dma(sq_size)
            .map_err(|_| "Failed to allocate ASQ DMA buffer")?;
        let asq_phys = asq_buffer.physical_address();
        let _asq_ptr = asq_buffer.as_ptr();

        let acq_buffer = kernel
            .alloc_dma(cq_size)
            .map_err(|_| "Failed to allocate ACQ DMA buffer")?;
        let acq_phys = acq_buffer.physical_address();
        let _acq_ptr = acq_buffer.as_ptr();

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
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        let kernel = kernel_api::services::kernel();
        let identify_buffer = kernel
            .alloc_dma(4096)
            .map_err(|_| "Failed to allocate Identify DMA buffer")?;
        let buffer_phys = identify_buffer.physical_address();

        let mut cmd = NvmeCommand::default();
        cmd.set_opcode(AdminOpcode::Identify as u8);
        cmd.set_cid(0);
        cmd.nsid = 0;
        cmd.set_prp(buffer_phys, 0);
        cmd.cdw10 = 1; // CNS = 1 (Identify Controller)

        admin_queue.submit(&cmd)?;

        for _ in 0..10000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                let status = cqe.status >> 1;
                if status != 0 {
                    kernel.free_dma(identify_buffer);
                    return Err("Identify Controller command failed");
                }
                let ctrl = unsafe { &*(identify_buffer.as_ptr() as *const IdentifyController) };
                self.identify_controller = Some(*ctrl);
                kernel.free_dma(identify_buffer);
                return Ok(());
            }
            core::hint::spin_loop();
        }

        kernel.free_dma(identify_buffer);
        Err("Identify Controller timeout")
    }

    /// Identify Namespaceコマンドを発行
    fn identify_namespace(&mut self, nsid: u32) -> Result<IdentifyNamespace, &'static str> {
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        let kernel = kernel_api::services::kernel();
        let identify_buffer = kernel
            .alloc_dma(4096)
            .map_err(|_| "Failed to allocate Identify Namespace DMA buffer")?;
        let buffer_phys = identify_buffer.physical_address();

        let cid = admin_queue.sq().tail();
        let cmd = NvmeCommand::identify_namespace(cid, nsid, buffer_phys);
        admin_queue.submit(&cmd)?;

        self.poll_admin_completion()?;

        let ns = unsafe { &*(identify_buffer.as_ptr() as *const IdentifyNamespace) };
        let ns_copy = *ns;

        if let Some(buf) = self.identify_buffer.take() {
            kernel.free_dma(buf);
        }
        self.identify_buffer = Some(identify_buffer);

        Ok(ns_copy)
    }

    /// Set Features - Number of Queuesを設定
    #[allow(dead_code)]
    fn set_num_queues(&mut self, num_sq: u16, num_cq: u16) -> Result<(u16, u16), &'static str> {
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

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
        self.cmb_info
            .as_mut()
            .and_then(|cmb| cmb.allocate_sq(depth))
    }

    /// CMBからCQバッファを割り当て（利用可能な場合）
    pub fn allocate_cq_from_cmb(&mut self, depth: u16) -> Option<u64> {
        self.cmb_info
            .as_mut()
            .and_then(|cmb| cmb.allocate_cq(depth))
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
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        let qid = (core_id + 1) as u16;

        // MSI-Xベクタ割り当て（Reactor Pattern）
        let entry = if self.interrupt_mode {
            // Kernel API経由でMSI-Xベクタを割り当て
            // Note: drivers crateからは直接kernel crateを呼べないため、
            // kernel_api::services などを通じてアクセスするか、
            // 事前に構成されたコールバックを使用する必要がある。
            // ここでは簡易的にベクタ48 + core_id を使用（設計書準拠）
            // 実装時には kernel_api への依存を追加するか、初期化時に注入する設計が望ましい。
            // 仮実装: 48 + core_id
            48 + core_id as u16
        } else {
            0
        };

        // Create I/O Completion Queue (cid=0 for first admin command of this queue)
        let create_cq_cmd =
            NvmeCommand::create_io_cq(0, qid, depth, cq_phys, entry, self.interrupt_mode);
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
            // Register for ISR access (Reactor Pattern)
            super::per_core::register_queue(core_id, queue);
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
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

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
        let max_queues = self.io_queue_count as u32;
        if max_queues == 0 || core_id >= max_queues {
            return None;
        }
        let queue = self.io_queues.get(core_id as usize)?;
        if queue.is_initialized() {
            Some(queue)
        } else {
            None
        }
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

        let completed = unsafe { queue.process_completions() };

        if completed == 0 {
            cpu_pause();
        }

        completed
    }

    /// リードコマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1/prp2は有効な物理アドレスである必要がある。
    pub unsafe fn submit_read(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.read(nsid, lba, blocks, prp1, prp2) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// リードコマンドを発行（SGL）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// sglは有効なデータブロック/セグメントディスクリプタである必要がある。
    pub unsafe fn submit_read_sgl(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.read_sgl(nsid, lba, blocks, sgl) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// ライトコマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1/prp2は有効な物理アドレスである必要がある。
    pub unsafe fn submit_write(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        prp1: u64,
        prp2: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.write(nsid, lba, blocks, prp1, prp2) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// ライトコマンドを発行（SGL）
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// sglは有効なデータブロック/セグメントディスクリプタである必要がある。
    pub unsafe fn submit_write_sgl(
        &self,
        core_id: u32,
        nsid: u32,
        lba: u64,
        blocks: u16,
        sgl: SglDescriptor,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.write_sgl(nsid, lba, blocks, sgl) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// Dataset Management (DSM) コマンドを発行 (TRIM等)
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1は有効な物理アドレスである必要がある (DSM Range Buffer)。
    /// prp2は現在未使用 (バッファサイズが1ページ以下を想定)。
    pub unsafe fn submit_dsm(
        &self,
        core_id: u32,
        nsid: u32,
        prp1: u64,
        _prp2: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        // nr=0 (1 range). async_ops.rs currently only constructs single-range DSMs.
        let cid = unsafe { queue.dataset_management(nsid, 0, prp1) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// SGL最大エントリ数を取得
    pub fn sgl_max_entries(&self) -> Option<usize> {
        let ctrl = self.identify_controller?;
        if (ctrl.sgls & SGLS_SUPPORTED) == 0 {
            return None;
        }
        if (ctrl.sgls & SGLS_DATA_BLOCK) == 0 {
            return None;
        }
        let max = if ctrl.msdbd == 0 {
            MAX_SGL_ENTRIES
        } else {
            ctrl.msdbd as usize
        };
        let max = max.min(MAX_SGL_ENTRIES);
        if max == 0 {
            None
        } else {
            Some(max)
        }
    }

    /// フラッシュコマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn submit_flush(&self, core_id: u32, nsid: u32) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.flush(nsid) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// Dataset Management (TRIM) コマンドを発行
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    /// prp1は有効な物理アドレスである必要がある。
    pub unsafe fn submit_dataset_management(
        &self,
        core_id: u32,
        nsid: u32,
        nr: u8,
        prp1: u64,
    ) -> Result<u16, &'static str> {
        let queue = self.get_queue(core_id).ok_or("Queue not found")?;
        let cid = unsafe { queue.dataset_management(nsid, nr, prp1) }?;
        unsafe { queue.flush_doorbell() };
        Ok(cid)
    }

    /// 特定のCIDの完了をポーリング
    ///
    /// # Safety
    /// 現在のコアIDが正しいことを呼び出し側が保証。
    pub unsafe fn poll_completion_by_cid(&self, core_id: u32, cid: u16) -> Option<NvmeCompletion> {
        let queue = self.get_queue(core_id)?;

        // ポーリングして完了を取得
        if let Some(cqe) = unsafe { queue.poll() } {
            // CIDが一致するかチェック
            if cqe.command_id() == cid {
                return Some(cqe);
            }
            // Note: CIDが一致しない場合は別のリクエストの完了
            // 完全な実装では、ペンディングキューで管理する必要がある
        }
        None
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

    /// 初期化済みI/Oキュー数を取得
    pub fn io_queue_count(&self) -> u16 {
        self.io_queue_count
    }

    /// 最大転送サイズを取得
    pub fn max_transfer_size(&self) -> usize {
        self.max_transfer_size
    }

    /// 統計を収集
    pub fn collect_stats(&self) -> NvmeDriverStats {
        let mut stats = NvmeDriverStats::default();

        for queue in self
            .io_queues
            .iter()
            .take(self.io_queue_count as usize)
        {
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

impl Drop for NvmePollingDriver {
    fn drop(&mut self) {
        // Free any allocated DMA buffers via KernelServices
        let kernel = kernel_api::services::kernel();

        if let Some(buf) = self.admin_sq_buffer.take() {
            kernel.free_dma(buf);
        }
        if let Some(buf) = self.admin_cq_buffer.take() {
            kernel.free_dma(buf);
        }
        if let Some(buf) = self.identify_buffer.take() {
            kernel.free_dma(buf);
        }
        for buf in self.io_sq_buffers.iter_mut().filter_map(|b| b.take()) {
            kernel.free_dma(buf);
        }
        for buf in self.io_cq_buffers.iter_mut().filter_map(|b| b.take()) {
            kernel.free_dma(buf);
        }
    }
}

/// CPU PAUSE命令（スピン待機の電力効率化）
#[inline(always)]
fn cpu_pause() {
    core::hint::spin_loop();
}

impl NvmePollingDriver {
    /// Wakerを登録（Reactor Pattern）
    pub fn register_waker(&self, core_id: u32, cid: u16, waker: core::task::Waker) {
        if let Some(queue) = self.get_queue(core_id) {
            queue.register_waker(cid, waker);
        }
    }

    /// 完了を確認（ソフトウェア状態のみチェック）
    pub fn check_completion(&self, core_id: u32, cid: u16) -> Option<NvmeCompletion> {
        if let Some(queue) = self.get_queue(core_id) {
            queue.check_completion(cid)
        } else {
            None
        }
    }

    /// 完了を取得してペンディングから削除
    pub fn take_completion(&self, core_id: u32, cid: u16) -> Option<NvmeCompletion> {
        if let Some(queue) = self.get_queue(core_id) {
            queue.take_completion(cid)
        } else {
            None
        }
    }

    /// 割り込みモードかどうか
    pub fn interrupt_mode(&self) -> bool {
        self.interrupt_mode
    }

    /// 名前空間の論理ブロックサイズ（バイト）
    pub fn namespace_block_size(&self, nsid: u32) -> u32 {
        if nsid == self.nsid {
            self.namespace_block_size
        } else {
            self.namespace_block_size
        }
    }
}
