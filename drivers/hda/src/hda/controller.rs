// ============================================================================
// src/io/audio/hda/controller.rs - HDA Controller Implementation
// ============================================================================
//!
//! Intel HD Audio コントローラの実装。
//!
//! - HdaController 構造体
//! - レジスタアクセス
//! - コントローラ初期化
//! - CORB/RIRB 管理
//! - コマンドインターフェース

#![allow(dead_code)]

use alloc::vec::Vec;
// Volatile memory reads/writes centralized via mmio helpers
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use crate::regs::*;
use crate::types::{CodecInfo, HdaError, HdaResult, make_corb_entry};

// ============================================================================
// HDA Controller
// ============================================================================

/// Intel HD Audio Controller
pub struct HdaController {
    /// Memory-mapped register base address
    pub(crate) mmio_base: u64,
    /// CORB buffer (virtual address for CPU access)
    pub(crate) corb_addr: u64,
    /// CORB buffer device address (IOVA or physical, for hardware register writes)
    pub(crate) corb_device_addr: u64,
    /// CORB buffer size
    pub(crate) corb_size: usize,
    /// CORB write pointer
    pub(crate) corb_wp: AtomicU16,
    /// RIRB buffer (virtual address for CPU access)
    pub(crate) rirb_addr: u64,
    /// RIRB buffer device address (IOVA or physical, for hardware register writes)
    pub(crate) rirb_device_addr: u64,
    /// RIRB buffer size
    pub(crate) rirb_size: usize,
    /// RIRB read pointer
    pub(crate) rirb_rp: AtomicU16,
    /// Detected codecs
    pub(crate) codecs: Vec<CodecInfo>,
    /// Number of input streams
    pub(crate) num_input_streams: u32,
    /// Number of output streams
    pub(crate) num_output_streams: u32,
    /// Number of bidirectional streams
    pub(crate) num_bidir_streams: u32,
    /// Controller initialized flag
    pub(crate) initialized: AtomicBool,
    /// DMA position buffer address
    pub(crate) dma_pos_addr: u64,
    /// Stream BDL virtual addresses (for CPU access)
    pub(crate) stream_bdl_addrs: [u64; 8],
    /// Stream BDL device addresses (for hardware register writes)
    pub(crate) stream_bdl_device_addrs: [u64; 8],
    /// Audio data buffer virtual addresses (for CPU access)
    pub(crate) audio_buffers: [u64; 8],
    /// Audio data buffer device addresses (for hardware/BDL)
    pub(crate) audio_buffer_device_addrs: [u64; 8],
}

// ============================================================================
// Safety Documentation for Send/Sync
// ============================================================================
//
// SAFETY INVARIANTS for HdaController:
// 1. mmio_base: Valid MMIO region from PCI BAR0, lifetime matches controller
// 2. corb_addr/rirb_addr: Allocated via alloc_dma_buffer(), 128-byte aligned
// 3. All register accesses use volatile operations
// 4. Concurrent access protected by Mutex<Option<HdaController>>
// 5. DMA operations use memory barriers (SFENCE/LFENCE) where required
//
// SAFETY: HdaController satisfies Send because:
// - All contained data is either primitive (u64, AtomicU16, etc.) or heap-allocated (Vec)
// - Raw pointer values (mmio_base, corb_addr, etc.) represent hardware resources
//   that remain valid for the lifetime of the kernel
// - Mutable state is protected by AtomicBool/AtomicU16 or external Mutex
unsafe impl Send for HdaController {}

// SAFETY: HdaController satisfies Sync because:
// - Read-only fields (mmio_base, num_*_streams) are immutable after init()
// - Mutable pointers (corb_wp, rirb_rp) use atomic operations
// - The global HDA_DRIVER uses Mutex for exclusive access
// - MMIO reads/writes are inherently atomic at hardware level for aligned accesses
unsafe impl Sync for HdaController {}

impl HdaController {
    /// Create a new HDA controller instance
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            corb_addr: 0,
            corb_device_addr: 0,
            corb_size: 0,
            corb_wp: AtomicU16::new(0),
            rirb_addr: 0,
            rirb_device_addr: 0,
            rirb_size: 0,
            rirb_rp: AtomicU16::new(0),
            codecs: Vec::new(),
            num_input_streams: 0,
            num_output_streams: 0,
            num_bidir_streams: 0,
            initialized: AtomicBool::new(false),
            dma_pos_addr: 0,
            stream_bdl_addrs: [0; 8],
            stream_bdl_device_addrs: [0; 8],
            audio_buffers: [0; 8],
            audio_buffer_device_addrs: [0; 8],
        }
    }

    // ========================================================================
    // Register Access
    // ========================================================================

    /// Read a 8-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be within the HDA register space
    #[inline]
    pub fn read8(&self, offset: u32) -> u8 {
        hal::mmio::mmio_read_u8((self.mmio_base + offset as u64) as usize)
    }

    /// Write a 8-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be within the HDA register space
    #[inline]
    pub fn write8(&self, offset: u32, value: u8) {
        hal::mmio::mmio_write_u8((self.mmio_base + offset as u64) as usize, value);
    }

    /// Read a 16-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 2-byte aligned and within the HDA register space
    #[inline]
    pub fn read16(&self, offset: u32) -> u16 {
        hal::mmio::mmio_read_u16((self.mmio_base + offset as u64) as usize)
    }

    /// Write a 16-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 2-byte aligned and within the HDA register space
    #[inline]
    pub fn write16(&self, offset: u32, value: u16) {
        hal::mmio::mmio_write_u16((self.mmio_base + offset as u64) as usize, value);
    }

    /// Read a 32-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 4-byte aligned and within the HDA register space
    #[inline]
    pub fn read32(&self, offset: u32) -> u32 {
        hal::mmio::mmio_read_u32((self.mmio_base + offset as u64) as usize)
    }

    /// Write a 32-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 4-byte aligned and within the HDA register space
    #[inline]
    pub fn write32(&self, offset: u32, value: u32) {
        hal::mmio::mmio_write_u32((self.mmio_base + offset as u64) as usize, value);
    }

    // ========================================================================
    // Controller Initialization
    // ========================================================================

    /// Initialize the HDA controller
    pub fn init(&mut self) -> HdaResult<()> {
        log::info!("[HDA] Initializing Intel HD Audio controller\n");

        // Read capabilities
        self.read_capabilities()?;

        // Reset controller
        self.reset_controller()?;

        // Initialize CORB
        self.init_corb()?;

        // Initialize RIRB
        self.init_rirb()?;

        // Enable controller interrupts (optional for polling mode)
        self.enable_interrupts();

        // Start CORB and RIRB DMA
        self.start_corb_rirb()?;

        // Detect codecs
        self.detect_codecs()?;

        // Initialize codecs
        self.init_codecs()?;

        self.initialized.store(true, Ordering::SeqCst);
        log::info!("[HDA] Controller initialized successfully\n");

        Ok(())
    }

    /// Read controller capabilities from GCAP register
    fn read_capabilities(&mut self) -> HdaResult<()> {
        let gcap = self.read16(REG_GCAP);
        let vmin = self.read8(REG_VMIN);
        let vmaj = self.read8(REG_VMAJ);

        // Parse GCAP
        // Bits 0: 64-bit address support
        // Bits 1-2: Number of serial data out signals
        // Bits 3-4: Number of bidirectional streams
        // Bits 5-7: Reserved
        // Bits 8-11: Number of input streams
        // Bits 12-15: Number of output streams

        self.num_input_streams = ((gcap >> 8) & 0x0F) as u32;
        self.num_output_streams = ((gcap >> 12) & 0x0F) as u32;
        self.num_bidir_streams = ((gcap >> 3) & 0x03) as u32;

        log::info!(
            "[HDA] Version: {}.{}, Streams: {} in, {} out, {} bidir\n",
            vmaj,
            vmin,
            self.num_input_streams,
            self.num_output_streams,
            self.num_bidir_streams
        );

        Ok(())
    }

    /// Reset the HDA controller
    fn reset_controller(&mut self) -> HdaResult<()> {
        log::info!("[HDA] Resetting controller...\n");

        // Enter reset: clear CRST bit
        let gctl = self.read32(REG_GCTL);
        self.write32(REG_GCTL, gctl & !GCTL_CRST);

        // Wait for controller to enter reset
        let mut timeout = RESET_TIMEOUT_US / 10;
        while timeout > 0 {
            if (self.read32(REG_GCTL) & GCTL_CRST) == 0 {
                break;
            }
            Self::delay_us(10);
            timeout -= 1;
        }

        if timeout == 0 {
            return Err(HdaError::ResetFailed);
        }

        // Small delay in reset state
        Self::delay_us(100);

        // Exit reset: set CRST bit
        let gctl = self.read32(REG_GCTL);
        self.write32(REG_GCTL, gctl | GCTL_CRST);

        // Wait for controller to exit reset
        timeout = RESET_TIMEOUT_US / 10;
        while timeout > 0 {
            if (self.read32(REG_GCTL) & GCTL_CRST) != 0 {
                break;
            }
            Self::delay_us(10);
            timeout -= 1;
        }

        if timeout == 0 {
            return Err(HdaError::ResetFailed);
        }

        // Wait for codec detection
        Self::delay_us(CODEC_TIMEOUT_US);

        log::info!("[HDA] Controller reset complete\n");
        Ok(())
    }

    /// Allocate a DMA buffer (aligned to 128 bytes)
    ///
    /// HDA specification requires CORB/RIRB and BDL buffers to be aligned
    /// to 128 bytes for proper DMA operation.
    ///
    /// Returns `(virt_addr, device_addr)` tuple where:
    /// - `virt_addr` is the CPU-accessible virtual address
    /// - `device_addr` is the hardware-visible address (IOVA or physical)
    pub fn alloc_dma_buffer(size: usize) -> HdaResult<(u64, u64)> {
        // Use kernel API for proper DMA allocation with IOMMU support
        match kernel_api::service::kernel::instance().alloc_dma(size) {
            Ok(buf) => {
                let virt = buf.as_ptr() as u64;
                let dev = buf.device_address();
                // Note: The buffer is managed by the kernel's DMA registry
                // and will be reclaimed automatically when the DMA slice is dropped.
                // We intentionally forget the buffer to prevent Drop from running,
                // as the kernel registry holds the actual allocation.
                core::mem::forget(buf);
                Ok((virt, dev))
            }
            Err(_) => Err(HdaError::AllocFailed),
        }
    }

    /// Initialize CORB (Command Output Ring Buffer)
    fn init_corb(&mut self) -> HdaResult<()> {
        log::info!("[HDA] Initializing CORB...\n");

        // Stop CORB if running
        self.write8(REG_CORBCTL, 0);
        Self::delay_us(100);

        // Read supported sizes
        let corbsize = self.read8(REG_CORBSIZE);
        let size_cap = (corbsize >> CORBSIZE_SZCAP_SHIFT) & 0x0F;

        // Select largest supported size
        let (size_entries, size_reg) = if (size_cap & 0x04) != 0 {
            (256, CORBSIZE_256)
        } else if (size_cap & 0x02) != 0 {
            (16, CORBSIZE_16)
        } else {
            (2, CORBSIZE_2)
        };

        self.corb_size = size_entries;

        // Allocate CORB buffer
        let buffer_size = size_entries * CORB_ENTRY_SIZE;
        let (virt, dev) = Self::alloc_dma_buffer(buffer_size)?;
        self.corb_addr = virt;
        self.corb_device_addr = dev;

        log::info!(
            "[HDA] CORB: {} entries at virt=0x{:016x} dev=0x{:016x}\n",
            size_entries,
            self.corb_addr,
            self.corb_device_addr
        );

        // Set CORB base address (hardware-visible device address)
        self.write32(REG_CORBLBASE, self.corb_device_addr as u32);
        self.write32(REG_CORBUBASE, (self.corb_device_addr >> 32) as u32);

        // Set CORB size
        self.write8(REG_CORBSIZE, size_reg);

        // Reset CORB read pointer
        self.write16(REG_CORBRP, CORBRP_RST);

        // Wait for reset to complete
        let mut timeout = 1000;
        while timeout > 0 {
            if (self.read16(REG_CORBRP) & CORBRP_RST) != 0 {
                break;
            }
            Self::delay_us(10);
            timeout -= 1;
        }

        // Clear reset bit
        self.write16(REG_CORBRP, 0);
        timeout = 1000;
        while timeout > 0 {
            if (self.read16(REG_CORBRP) & CORBRP_RST) == 0 {
                break;
            }
            Self::delay_us(10);
            timeout -= 1;
        }

        // Reset write pointer
        self.write16(REG_CORBWP, 0);
        self.corb_wp.store(0, Ordering::SeqCst);

        log::info!("[HDA] CORB initialized\n");
        Ok(())
    }

    /// Initialize RIRB (Response Input Ring Buffer)
    fn init_rirb(&mut self) -> HdaResult<()> {
        log::info!("[HDA] Initializing RIRB...\n");

        // Stop RIRB if running
        self.write8(REG_RIRBCTL, 0);
        Self::delay_us(100);

        // Read supported sizes
        let rirbsize = self.read8(REG_RIRBSIZE);
        let size_cap = (rirbsize >> RIRBSIZE_SZCAP_SHIFT) & 0x0F;

        // Select largest supported size
        let (size_entries, size_reg) = if (size_cap & 0x04) != 0 {
            (256, RIRBSIZE_256)
        } else if (size_cap & 0x02) != 0 {
            (16, RIRBSIZE_16)
        } else {
            (2, RIRBSIZE_2)
        };

        self.rirb_size = size_entries;

        // Allocate RIRB buffer
        let buffer_size = size_entries * RIRB_ENTRY_SIZE;
        let (virt, dev) = Self::alloc_dma_buffer(buffer_size)?;
        self.rirb_addr = virt;
        self.rirb_device_addr = dev;

        log::info!(
            "[HDA] RIRB: {} entries at virt=0x{:016x} dev=0x{:016x}\n",
            size_entries,
            self.rirb_addr,
            self.rirb_device_addr
        );

        // Set RIRB base address (hardware-visible device address)
        self.write32(REG_RIRBLBASE, self.rirb_device_addr as u32);
        self.write32(REG_RIRBUBASE, (self.rirb_device_addr >> 32) as u32);

        // Set RIRB size
        self.write8(REG_RIRBSIZE, size_reg);

        // Reset RIRB write pointer
        self.write16(REG_RIRBWP, RIRBWP_RST);

        // Set response interrupt count
        self.write16(REG_RINTCNT, 1);

        // Reset read pointer
        self.rirb_rp.store(0, Ordering::SeqCst);

        log::info!("[HDA] RIRB initialized\n");
        Ok(())
    }

    /// Enable controller interrupts
    fn enable_interrupts(&self) {
        // Enable global and controller interrupts
        self.write32(REG_INTCTL, INTCTL_GIE | INTCTL_CIE);
    }

    /// Start CORB and RIRB DMA engines
    fn start_corb_rirb(&self) -> HdaResult<()> {
        log::info!("[HDA] Starting CORB/RIRB DMA...\n");

        // Start RIRB DMA
        self.write8(REG_RIRBCTL, RIRBCTL_DMAEN | RIRBCTL_RINTCTL);

        // Start CORB DMA
        self.write8(REG_CORBCTL, CORBCTL_CORBRUN);

        // Verify DMA is running
        Self::delay_us(100);

        let corbctl = self.read8(REG_CORBCTL);
        let rirbctl = self.read8(REG_RIRBCTL);

        if (corbctl & CORBCTL_CORBRUN) == 0 {
            return Err(HdaError::InitFailed("CORB DMA failed to start".into()));
        }

        if (rirbctl & RIRBCTL_DMAEN) == 0 {
            return Err(HdaError::InitFailed("RIRB DMA failed to start".into()));
        }

        log::info!("[HDA] CORB/RIRB DMA started\n");
        Ok(())
    }

    // ========================================================================
    // Command Interface
    // ========================================================================

    /// Send a command via CORB and wait for response via RIRB
    pub fn send_command(&self, codec_addr: u8, node_id: u8, verb: u32) -> HdaResult<u32> {
        // Build command
        let cmd = make_corb_entry(codec_addr, node_id, verb);

        // Get current write pointer and calculate next
        let wp = self.corb_wp.load(Ordering::SeqCst);
        let next_wp = ((wp as usize + 1) % self.corb_size) as u16;

        // Write command to CORB
        let corb_entry_addr = self.corb_addr + (next_wp as u64 * CORB_ENTRY_SIZE as u64);
        // SAFETY: corb_entry_addr points to a valid DMA buffer entry allocated by alloc_dma_buffer.
        // The buffer is 128-byte aligned and within bounds (next_wp < corb_size).
        hal::mmio::mmio_write_u32(corb_entry_addr as usize, cmd);

        // SAFETY: SFENCE ensures the CORB entry write is visible to the HDA controller
        // before we update the write pointer. This prevents out-of-order writes
        // that could cause the controller to read incomplete command data.
        // Use hal::mmio::sfence() which has proper target_feature guards
        hal::mmio::sfence();

        // Update write pointer
        self.write16(REG_CORBWP, next_wp);
        self.corb_wp.store(next_wp, Ordering::SeqCst);

        // Wait for response
        self.wait_for_response()
    }

    /// Wait for a response in RIRB
    fn wait_for_response(&self) -> HdaResult<u32> {
        let mut timeout = CMD_TIMEOUT_US / 10;

        let rp = self.rirb_rp.load(Ordering::SeqCst);

        while timeout > 0 {
            let wp = self.read16(REG_RIRBWP);

            if wp != rp {
                // New response available
                let next_rp = ((rp as usize + 1) % self.rirb_size) as u16;

                // SAFETY: LFENCE ensures all previous loads complete and that we see
                // the latest data written by the HDA controller to the RIRB buffer.
                // While x86_64 provides cache coherency for DMA, the fence ensures
                // speculative loads don't return stale data.
                // Use target_feature guard for SSE intrinsics
                #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
                unsafe {
                    core::arch::x86_64::_mm_lfence()
                };
                #[cfg(not(all(target_arch = "x86_64", target_feature = "sse2")))]
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);

                // Read response
                let rirb_entry_addr = self.rirb_addr + (next_rp as u64 * RIRB_ENTRY_SIZE as u64);
                // SAFETY: rirb_entry_addr points to a valid DMA buffer entry allocated by alloc_dma_buffer.
                // The buffer is 128-byte aligned and within bounds (next_rp < rirb_size).
                let response = hal::mmio::mmio_read_u32(rirb_entry_addr as usize);

                // Update read pointer
                self.rirb_rp.store(next_rp, Ordering::SeqCst);

                return Ok(response);
            }

            Self::delay_us(10);
            timeout -= 1;
        }

        Err(HdaError::Timeout)
    }

    /// Get parameter from a codec node
    pub fn get_parameter(&self, codec_addr: u8, node_id: u8, param_id: u8) -> HdaResult<u32> {
        let verb = VERB_GET_PARAM | (param_id as u32);
        self.send_command(codec_addr, node_id, verb)
    }

    // ========================================================================
    // Codec Detection and Initialization (delegated to codec module)
    // ========================================================================

    /// Detect connected codecs
    pub fn detect_codecs(&mut self) -> HdaResult<()> {
        // Driver-level helper returns list of detected codecs; store locally
        self.codecs = super::codec::detect_codecs();
        Ok(())
    }

    /// Initialize detected codecs
    pub fn init_codecs(&mut self) -> HdaResult<()> {
        super::codec::init_codecs(&mut self.codecs)
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /// Microsecond delay (PIT タイマーベース)
    ///
    /// 従来の spin_loop による空回しから PIT ワンショットモードに変更。
    /// より正確な時間待機が可能になる。
    pub fn delay_us(us: u64) {
        // Simple spin loop approximate delay for now, as PIT is kernel-internal
        // TODO: Pass a timer trait or use a better HAL delay
        let iterations = us * 100; // Rough estimate
        for _ in 0..iterations {
            core::hint::spin_loop();
        }
    }

    /// Get codec information
    pub fn codecs(&self) -> &[CodecInfo] {
        &self.codecs
    }

    /// Check if controller is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }
}
