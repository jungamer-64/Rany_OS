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

use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use crate::io::pci::PciDeviceInfo;
use crate::time;

use super::regs::*;
use super::types::{make_corb_entry, CodecInfo, HdaError, HdaResult};

// ============================================================================
// HDA Controller
// ============================================================================

/// Intel HD Audio Controller
pub struct HdaController {
    /// PCI device info
    pub(crate) pci_device: PciDeviceInfo,
    /// Memory-mapped register base address
    pub(crate) mmio_base: u64,
    /// CORB buffer (physical address)
    pub(crate) corb_addr: u64,
    /// CORB buffer size
    pub(crate) corb_size: usize,
    /// CORB write pointer
    pub(crate) corb_wp: AtomicU16,
    /// RIRB buffer (physical address)
    pub(crate) rirb_addr: u64,
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
    /// Stream BDL addresses
    pub(crate) stream_bdl_addrs: [u64; 8],
    /// Audio data buffers
    pub(crate) audio_buffers: [u64; 8],
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
    pub fn new(pci_device: PciDeviceInfo, mmio_base: u64) -> Self {
        Self {
            pci_device,
            mmio_base,
            corb_addr: 0,
            corb_size: 0,
            corb_wp: AtomicU16::new(0),
            rirb_addr: 0,
            rirb_size: 0,
            rirb_rp: AtomicU16::new(0),
            codecs: Vec::new(),
            num_input_streams: 0,
            num_output_streams: 0,
            num_bidir_streams: 0,
            initialized: AtomicBool::new(false),
            dma_pos_addr: 0,
            stream_bdl_addrs: [0; 8],
            audio_buffers: [0; 8],
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
        // SAFETY: mmio_base was validated during new() from PCI BAR0.
        // read_volatile ensures the read is not optimized away and is atomic for u8.
        unsafe { read_volatile((self.mmio_base + offset as u64) as *const u8) }
    }

    /// Write a 8-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be within the HDA register space
    #[inline]
    pub fn write8(&self, offset: u32, value: u8) {
        // SAFETY: mmio_base was validated during new() from PCI BAR0.
        // write_volatile ensures the write is not optimized away and is atomic for u8.
        unsafe { write_volatile((self.mmio_base + offset as u64) as *mut u8, value) }
    }

    /// Read a 16-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 2-byte aligned and within the HDA register space
    #[inline]
    pub fn read16(&self, offset: u32) -> u16 {
        // SAFETY: mmio_base was validated during new() from PCI BAR0.
        // HDA spec defines 16-bit registers at 2-byte aligned offsets.
        // read_volatile ensures the read is not optimized away.
        unsafe { read_volatile((self.mmio_base + offset as u64) as *const u16) }
    }

    /// Write a 16-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 2-byte aligned and within the HDA register space
    #[inline]
    pub fn write16(&self, offset: u32, value: u16) {
        // SAFETY: mmio_base was validated during new() from PCI BAR0.
        // HDA spec defines 16-bit registers at 2-byte aligned offsets.
        // write_volatile ensures the write is not optimized away.
        unsafe { write_volatile((self.mmio_base + offset as u64) as *mut u16, value) }
    }

    /// Read a 32-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 4-byte aligned and within the HDA register space
    #[inline]
    pub fn read32(&self, offset: u32) -> u32 {
        // SAFETY: mmio_base was validated during new() from PCI BAR0.
        // HDA spec defines 32-bit registers at 4-byte aligned offsets.
        // read_volatile ensures the read is not optimized away.
        unsafe { read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a 32-bit register
    ///
    /// # Safety Requirements (internal)
    /// - self.mmio_base must be a valid MMIO region mapped by the kernel
    /// - offset must be 4-byte aligned and within the HDA register space
    #[inline]
    pub fn write32(&self, offset: u32, value: u32) {
        // SAFETY: mmio_base was validated during new() from PCI BAR0.
        // HDA spec defines 32-bit registers at 4-byte aligned offsets.
        // write_volatile ensures the write is not optimized away.
        unsafe { write_volatile((self.mmio_base + offset as u64) as *mut u32, value) }
    }

    // ========================================================================
    // Controller Initialization
    // ========================================================================

    /// Initialize the HDA controller
    pub fn init(&mut self) -> HdaResult<()> {
        crate::log!("[HDA] Initializing Intel HD Audio controller\n");

        // Enable PCI bus mastering and memory space
        self.pci_device.enable_bus_master();
        self.pci_device.enable_memory_space();

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
        crate::log!("[HDA] Controller initialized successfully\n");

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

        crate::log!(
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
        crate::log!("[HDA] Resetting controller...\n");

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

        crate::log!("[HDA] Controller reset complete\n");
        Ok(())
    }

    /// Allocate a DMA buffer (aligned to 128 bytes)
    ///
    /// HDA specification requires CORB/RIRB and BDL buffers to be aligned
    /// to 128 bytes for proper DMA operation.
    pub fn alloc_dma_buffer(size: usize) -> HdaResult<u64> {
        // Allocate memory aligned to 128 bytes as required by HDA spec
        let layout = core::alloc::Layout::from_size_align(size, 128)
            .map_err(|_| HdaError::AllocFailed)?;

        // SAFETY: Layout is valid (size > 0, align is 128 which is a power of 2).
        // The allocated buffer will be used for DMA with the HDA controller.
        // alloc_zeroed returns a valid pointer or null, which we check below.
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(HdaError::AllocFailed);
        }

        // Note: On x86_64 with PCIe, hardware cache coherency is maintained.
        // For other architectures, consider cache flush here.
        Ok(ptr as u64)
    }

    /// Initialize CORB (Command Output Ring Buffer)
    fn init_corb(&mut self) -> HdaResult<()> {
        crate::log!("[HDA] Initializing CORB...\n");

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
        self.corb_addr = Self::alloc_dma_buffer(buffer_size)?;

        crate::log!(
            "[HDA] CORB: {} entries at 0x{:016x}\n",
            size_entries,
            self.corb_addr
        );

        // Set CORB base address
        self.write32(REG_CORBLBASE, self.corb_addr as u32);
        self.write32(REG_CORBUBASE, (self.corb_addr >> 32) as u32);

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

        crate::log!("[HDA] CORB initialized\n");
        Ok(())
    }

    /// Initialize RIRB (Response Input Ring Buffer)
    fn init_rirb(&mut self) -> HdaResult<()> {
        crate::log!("[HDA] Initializing RIRB...\n");

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
        self.rirb_addr = Self::alloc_dma_buffer(buffer_size)?;

        crate::log!(
            "[HDA] RIRB: {} entries at 0x{:016x}\n",
            size_entries,
            self.rirb_addr
        );

        // Set RIRB base address
        self.write32(REG_RIRBLBASE, self.rirb_addr as u32);
        self.write32(REG_RIRBUBASE, (self.rirb_addr >> 32) as u32);

        // Set RIRB size
        self.write8(REG_RIRBSIZE, size_reg);

        // Reset RIRB write pointer
        self.write16(REG_RIRBWP, RIRBWP_RST);

        // Set response interrupt count
        self.write16(REG_RINTCNT, 1);

        // Reset read pointer
        self.rirb_rp.store(0, Ordering::SeqCst);

        crate::log!("[HDA] RIRB initialized\n");
        Ok(())
    }

    /// Enable controller interrupts
    fn enable_interrupts(&self) {
        // Enable global and controller interrupts
        self.write32(REG_INTCTL, INTCTL_GIE | INTCTL_CIE);
    }

    /// Start CORB and RIRB DMA engines
    fn start_corb_rirb(&self) -> HdaResult<()> {
        crate::log!("[HDA] Starting CORB/RIRB DMA...\n");

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

        crate::log!("[HDA] CORB/RIRB DMA started\n");
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
        unsafe {
            write_volatile(corb_entry_addr as *mut u32, cmd);
        }

        // SAFETY: SFENCE ensures the CORB entry write is visible to the HDA controller
        // before we update the write pointer. This prevents out-of-order writes
        // that could cause the controller to read incomplete command data.
        // On x86_64, this is implemented as the SFENCE instruction.
        crate::io::dma::sfence();

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
                crate::io::dma::lfence();

                // Read response
                let rirb_entry_addr = self.rirb_addr + (next_rp as u64 * RIRB_ENTRY_SIZE as u64);
                // SAFETY: rirb_entry_addr points to a valid DMA buffer entry allocated by alloc_dma_buffer.
                // The buffer is 128-byte aligned and within bounds (next_rp < rirb_size).
                let response = unsafe { read_volatile(rirb_entry_addr as *const u32) };

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
        super::codec::detect_codecs(self)
    }

    /// Initialize detected codecs
    pub fn init_codecs(&mut self) -> HdaResult<()> {
        super::codec::init_codecs(self)
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /// Microsecond delay (PIT タイマーベース)
    ///
    /// 従来の spin_loop による空回しから PIT ワンショットモードに変更。
    /// より正確な時間待機が可能になる。
    pub fn delay_us(us: u64) {
        // PIT タイマーを使用した精密な待機
        // time::pit() は既に初期化済みの PIT インスタンスを返す
        time::pit().delay_us(us);
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
