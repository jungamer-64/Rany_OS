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
use kernel_api::dma::{CpuOwned, DmaSlice};

type DmaBuffer = DmaSlice<CpuOwned>;

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
mod drop_and_helpers;
use drop_and_helpers::*;
mod admin_polling;

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
    /// 名前空間の総ブロック数（nsze）
    namespace_total_blocks: u64,
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
    /// IOMMU対応デバイスID（packed u64: segment|bus|device|function）
    /// 設定時は `alloc_dma_for_device()` でIOMMUマッピング付きDMAバッファを割り当てる
    device_id: Option<u64>,
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
    ///
    /// `device_id` にはIOMMU対応のパック済みデバイスIDを指定する。
    /// IOMMU有効環境ではDMAバッファがデバイス固有ドメインにマッピングされる。
    pub fn new(bar0: u64, num_cores: u32, device_id: Option<u64>) -> Self {
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
            namespace_total_blocks: 0,
            allocated_sq_count: 0,
            allocated_cq_count: 0,
            active: AtomicBool::new(false),
            interrupt_mode: false, // ポーリングモードをデフォルトにする
            cmb_info: None,
            use_cmb: true, // デフォルトでCMBを使用（利用可能なら）
            device_id,
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

    /// CMB（Controller Memory Buffer）を初期化
    fn init_cmb(&mut self) {
        if !self.use_cmb {
            return;
        }
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

    /// ネームスペース情報を取得しブロックサイズを設定
    fn identify_and_configure_namespace(&mut self) {
        if let Err(err) = self.identify_controller() {
            log::warn!("[NVME] Identify Controller failed: {}", err);
        }

        // Identify Namespaceでブロックサイズと総ブロック数を取得
        if let Ok(ns) = self.identify_namespace(self.nsid) {
            let block_size = ns.block_size() as u32;
            if block_size != 0 {
                self.namespace_block_size = block_size;
            }
            self.namespace_total_blocks = ns.nsze;
        }
    }

    /// コントローラを初期化
    pub fn init(&mut self) -> Result<(), &'static str> {
        // CAP レジスタを読む
        let cap_raw = self.read_reg64(0x00);
        self.cap = NvmeCapabilities::new(cap_raw);

        // ドアベルストライドを計算
        self.doorbell_stride = self.cap.doorbell_stride_bytes();
        self.max_queue_depth = self.cap.max_queue_depth().min(MAX_QUEUE_DEPTH as u32) as u16;

        // CMB情報を取得
        self.init_cmb();

        // コントローラを無効化
        self.disable_controller()?;

        // Admin Queueのセットアップ
        let admin_depth = (DEFAULT_QUEUE_DEPTH as u32).min(self.cap.max_queue_depth()) as u16;
        self.init_admin_queue(admin_depth)?;

        // コントローラを有効化
        self.enable_controller()?;

        self.identify_and_configure_namespace();

        // I/Oキューを初期化
        let num_cores = self.io_queues.len() as u32;
        self.init_io_queues(num_cores)?;

        self.active.store(true, Ordering::Release);

        Ok(())
    }

    /// IOMMU対応DMAバッファを割り当てる（device_id設定時はIOMMUマッピング付き）
    fn alloc_dma_for_driver(
        &self,
        size: usize,
        alloc_err: &'static str,
    ) -> Result<DmaBuffer, &'static str> {
        let kernel = kernel_api::service::kernel::instance();
        let buffer = match self.device_id {
            Some(dev_id) => kernel.alloc_dma_for_device(size, dev_id),
            None => kernel.alloc_dma(size),
        }
        .map_err(|_| alloc_err)?;
        // Ensure both physical and device addresses are aligned
        if (buffer.physical_address() & 0xFFF != 0) || (buffer.device_address() & 0xFFF != 0) {
            return Err("DMA buffer not 4KB aligned");
        }
        Ok(buffer)
    }

    /// Allocate and create a single I/O queue pair for the given core.
    fn allocate_io_queue_for_core(&mut self, core_id: u32, depth: u16) -> Result<(), &'static str> {
        let cq_size = (depth as usize) * CQ_ENTRY_SIZE;
        let sq_size = (depth as usize) * QUEUE_ENTRY_SIZE;

        // CQバッファはホストメモリから確保
        let cq_buffer =
            self.alloc_dma_for_driver(cq_size, "Failed to allocate IO CQ DMA buffer")?;
        let cq_phys = cq_buffer.device_address();
        let cq_ptr = cq_buffer.as_ptr() as *mut NvmeCompletion;

        // SQはCMB優先（利用不可ならホストメモリ）
        if self.use_cmb && self.has_cmb() {
            if let Ok((_qid, _sq_addr)) =
                self.create_io_queue_with_cmb(core_id, cq_ptr, cq_phys, depth)
            {
                self.io_cq_buffers[core_id as usize] = Some(cq_buffer);
                return Ok(());
            }
        }

        let sq_buffer =
            self.alloc_dma_for_driver(sq_size, "Failed to allocate IO SQ DMA buffer")?;
        let sq_phys = sq_buffer.device_address();
        let sq_ptr = sq_buffer.as_ptr() as *mut NvmeCommand;

        self.create_io_queue_pair_internal(core_id, sq_ptr, cq_ptr, sq_phys, cq_phys, depth)?;

        self.io_sq_buffers[core_id as usize] = Some(sq_buffer);
        self.io_cq_buffers[core_id as usize] = Some(cq_buffer);
        Ok(())
    }

    /// I/Oキューを初期化
    fn init_io_queues(&mut self, num_cores: u32) -> Result<(), &'static str> {
        if num_cores == 0 {
            return Err("No cores available for I/O queues");
        }

        // コントローラに対してI/Oキュー数を要求
        let (allocated_sq, allocated_cq) = self
            .set_num_queues(num_cores as u16, num_cores as u16)
            .unwrap_or((1, 1));
        let io_queue_count = core::cmp::min(allocated_sq, allocated_cq).min(num_cores as u16);
        if io_queue_count == 0 {
            return Err("No I/O queues allocated by controller");
        }

        let depth = self.max_queue_depth.min(DEFAULT_QUEUE_DEPTH as u16).max(2);

        for core_id in 0..io_queue_count as u32 {
            self.allocate_io_queue_for_core(core_id, depth)?;
        }

        self.io_queue_count = self.allocated_sq_count;

        Ok(())
    }

    /// Admin Queueを初期化
    fn init_admin_queue(&mut self, depth: u16) -> Result<(), &'static str> {
        let sq_size = (depth as usize) * QUEUE_ENTRY_SIZE;
        let cq_size = (depth as usize) * CQ_ENTRY_SIZE;

        // Alloc DMA via IOMMU-aware method
        let asq_buffer = self.alloc_dma_for_driver(sq_size, "Failed to allocate ASQ DMA buffer")?;
        let asq_phys = asq_buffer.device_address();
        let _asq_ptr = asq_buffer.as_ptr();

        let acq_buffer = self.alloc_dma_for_driver(cq_size, "Failed to allocate ACQ DMA buffer")?;
        let acq_phys = acq_buffer.device_address();
        let _acq_ptr = acq_buffer.as_ptr();

        if asq_phys & 0xFFF != 0 || acq_phys & 0xFFF != 0 {
            return Err("DMA buffer not 4KB aligned");
        }

        unsafe {
            self.setup_admin_queue(asq_phys, acq_phys, depth)?;
        }

        let sq_doorbell = (self.bar0 + 0x1000) as *mut u32;
        let cq_doorbell = (self.bar0 + 0x1000 + self.doorbell_stride as u64) as *mut u32;

        // QueuePair::new() にはCPU仮想アドレスを渡す（IOVAではない）
        let asq_cpu_ptr = asq_buffer.as_ptr() as *mut NvmeCommand;
        let acq_cpu_ptr = acq_buffer.as_ptr() as *mut NvmeCompletion;

        let admin_qp = unsafe {
            QueuePair::new(
                asq_cpu_ptr,
                acq_cpu_ptr,
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

        let kernel = kernel_api::service::kernel::instance();
        let identify_buffer = match self.device_id {
            Some(dev_id) => kernel.alloc_dma_for_device(4096, dev_id),
            None => kernel.alloc_dma(4096),
        }
        .map_err(|_| "Failed to allocate Identify DMA buffer")?;
        let buffer_phys = identify_buffer.device_address();

        let mut cmd = NvmeCommand::default();
        cmd.set_opcode(AdminOpcode::Identify as u8);
        cmd.set_cid(0);
        cmd.nsid = 0;
        cmd.set_prp(buffer_phys, 0);
        cmd.cdw10 = 1; // CNS = 1 (Identify Controller)

        admin_queue.submit(&cmd)?;

        // NVMeスペック上、コントローラは最大数百ms応答に要する場合がある。
        // 10,000,000回のスピンループ ≈ 100-200ms（PAUSE命令 ≈ 10-20ns）
        for _ in 0..10_000_000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                let status = cqe.status >> 1;
                if status != 0 {
                    log::error!(
                        "[NVME] Identify Controller failed: status=0x{:04x} SCT={} SC=0x{:02x} CID={}",
                        cqe.status,
                        cqe.sct(),
                        cqe.sc(),
                        cqe.command_id()
                    );
                    drop(identify_buffer);
                    return Err("Identify Controller command failed");
                }
                let ctrl = unsafe { &*(identify_buffer.as_ptr() as *const IdentifyController) };
                self.identify_controller = Some(*ctrl);
                drop(identify_buffer);
                return Ok(());
            }
            core::hint::spin_loop();
        }

        drop(identify_buffer);
        Err("Identify Controller timeout")
    }

    /// Identify Namespaceコマンドを発行
    fn identify_namespace(&mut self, nsid: u32) -> Result<IdentifyNamespace, &'static str> {
        let admin_queue = self
            .admin_queue
            .as_ref()
            .ok_or("Admin queue not initialized")?;

        let kernel = kernel_api::service::kernel::instance();
        let identify_buffer = match self.device_id {
            Some(dev_id) => kernel.alloc_dma_for_device(4096, dev_id),
            None => kernel.alloc_dma(4096),
        }
        .map_err(|_| "Failed to allocate Identify Namespace DMA buffer")?;
        let buffer_phys = identify_buffer.device_address();

        let cid = admin_queue.sq().tail();
        let cmd = NvmeCommand::identify_namespace(cid, nsid, buffer_phys);
        admin_queue.submit(&cmd)?;

        self.poll_admin_completion()?;

        let ns = unsafe { &*(identify_buffer.as_ptr() as *const IdentifyNamespace) };
        let ns_copy = *ns;

        if let Some(buf) = self.identify_buffer.take() {
            drop(buf);
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

        // NVMeスペック準拠: 十分な待機（10M回 ≈ 100-200ms）
        for _ in 0..10_000_000 {
            if let Some(cqe) = admin_queue.poll_completion() {
                let status = cqe.status >> 1;
                if status != 0 {
                    log::error!(
                        "[NVME] Set Features (Number of Queues) failed: status=0x{:04x} SCT={} SC=0x{:02x}",
                        cqe.status,
                        cqe.sct(),
                        cqe.sc()
                    );
                    return Err("Set Features failed");
                }
                let allocated_sq = ((cqe.result & 0xFFFF) + 1) as u16;
                let allocated_cq = (((cqe.result >> 16) & 0xFFFF) + 1) as u16;
                log::info!(
                    "[NVME] Set Features: allocated {} SQ, {} CQ",
                    allocated_sq,
                    allocated_cq
                );
                return Ok((allocated_sq, allocated_cq));
            }
            core::hint::spin_loop();
        }

        log::error!("[NVME] Set Features (Number of Queues) timed out after 10M iterations");
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
        log::debug!(
            "[NVME] Creating I/O CQ qid={} depth={} phys=0x{:x} irq_vec={}",
            qid,
            depth,
            cq_phys,
            entry
        );
        admin_queue.submit(&create_cq_cmd)?;
        self.poll_admin_completion_named("Create I/O CQ")?;

        // Create I/O Submission Queue (cid=1 for second admin command of this queue)
        let create_sq_cmd = NvmeCommand::create_io_sq(1, qid, depth, sq_phys, qid, 0);
        log::debug!(
            "[NVME] Creating I/O SQ qid={} depth={} phys=0x{:x}",
            qid,
            depth,
            sq_phys
        );
        admin_queue.submit(&create_sq_cmd)?;
        self.poll_admin_completion_named("Create I/O SQ")?;

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
}
