// ============================================================================
// src/io/audio/hda.rs - Intel High Definition Audio Driver
// ============================================================================
//!
//! # Intel HD Audio ドライバ
//!
//! QEMUの intel-hda デバイス用のHDAドライバ実装。
//! CORB/RIRBを使用したコーデック通信と基本的なオーディオ出力をサポート。
//!
//! ## 機能
//! - PCIデバイス検出
//! - CORB/RIRB初期化
//! - コーデック検出
//! - ビープ音生成

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Mutex;

use crate::io::pci::{find_by_class, PciBar, PciDevice};
use crate::time;
use crate::task::interrupt_waker;

use super::regs::*;

// ============================================================================
// Interrupt Support
// ============================================================================

/// HDA 割り込みベクタ番号
/// PCI デバイスの interrupt_line から動的に決定される
static HDA_IRQ: AtomicU8 = AtomicU8::new(0);
use core::sync::atomic::AtomicU8;

/// HDA 割り込み発生カウンタ（デバッグ用）
static HDA_INTERRUPT_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// HDA 割り込みペンディングフラグ
static HDA_INTERRUPT_PENDING: AtomicBool = AtomicBool::new(false);

// ============================================================================
// Error Types
// ============================================================================

/// HDA Driver Error
#[derive(Debug, Clone)]
pub enum HdaError {
    /// No HDA device found
    NoDevice,
    /// Device initialization failed
    InitFailed(String),
    /// Invalid BAR configuration
    InvalidBar,
    /// Controller reset failed
    ResetFailed,
    /// Codec not found
    NoCodec,
    /// Command timeout
    Timeout,
    /// Invalid response
    InvalidResponse,
    /// Memory allocation failed
    AllocFailed,
    /// Stream configuration failed
    StreamError(String),
}

pub type HdaResult<T> = Result<T, HdaError>;

// ============================================================================
// CORB Entry
// ============================================================================

/// Build a CORB command entry
/// Format: [Codec Address (4)] [Node ID (8)] [Verb (20)]
#[inline]
pub fn make_corb_entry(codec_addr: u8, node_id: u8, verb: u32) -> u32 {
    ((codec_addr as u32 & 0x0F) << 28) | ((node_id as u32) << 20) | (verb & 0xFFFFF)
}

// ============================================================================
// RIRB Entry
// ============================================================================

/// RIRB Response Entry
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RirbEntry {
    /// Response data
    pub response: u32,
    /// Response extended (codec address, unsolicited flag)
    pub response_ex: u32,
}

impl RirbEntry {
    /// Get codec address from response
    pub fn codec_addr(&self) -> u8 {
        (self.response_ex & 0x0F) as u8
    }

    /// Check if this is an unsolicited response
    pub fn is_unsolicited(&self) -> bool {
        (self.response_ex & 0x10) != 0
    }
}

// ============================================================================
// Buffer Descriptor List Entry
// ============================================================================

/// Buffer Descriptor List entry for audio DMA
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct BdlEntry {
    /// Buffer address (lower 32 bits)
    pub addr_lo: u32,
    /// Buffer address (upper 32 bits)
    pub addr_hi: u32,
    /// Buffer length in bytes
    pub length: u32,
    /// Interrupt on completion flag
    pub ioc: u32,
}

impl BdlEntry {
    /// Create a new BDL entry
    pub fn new(addr: u64, length: u32, ioc: bool) -> Self {
        Self {
            addr_lo: addr as u32,
            addr_hi: (addr >> 32) as u32,
            length,
            ioc: if ioc { BDL_IOC } else { 0 },
        }
    }
}

// ============================================================================
// Codec Node Information
// ============================================================================

/// Codec node type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    Root,
    AudioFunctionGroup,
    AudioOutput,
    AudioInput,
    AudioMixer,
    AudioSelector,
    PinComplex,
    PowerWidget,
    VolumeKnob,
    BeepGenerator,
    VendorDefined,
    Unknown(u8),
}

impl From<u8> for NodeType {
    fn from(v: u8) -> Self {
        match v {
            WIDGET_TYPE_AUDIO_OUTPUT => NodeType::AudioOutput,
            WIDGET_TYPE_AUDIO_INPUT => NodeType::AudioInput,
            WIDGET_TYPE_AUDIO_MIXER => NodeType::AudioMixer,
            WIDGET_TYPE_AUDIO_SELECTOR => NodeType::AudioSelector,
            WIDGET_TYPE_PIN_COMPLEX => NodeType::PinComplex,
            WIDGET_TYPE_POWER => NodeType::PowerWidget,
            WIDGET_TYPE_VOLUME_KNOB => NodeType::VolumeKnob,
            WIDGET_TYPE_BEEP_GEN => NodeType::BeepGenerator,
            WIDGET_TYPE_VENDOR => NodeType::VendorDefined,
            _ => NodeType::Unknown(v),
        }
    }
}

/// Audio widget capabilities
#[derive(Debug, Clone, Copy)]
pub struct WidgetCaps {
    /// Widget type
    pub widget_type: NodeType,
    /// Has connection list
    pub conn_list: bool,
    /// Has output amplifier
    pub out_amp: bool,
    /// Has input amplifier
    pub in_amp: bool,
    /// Supports format override
    pub format_override: bool,
    /// Stereo capability
    pub stereo: bool,
}

impl From<u32> for WidgetCaps {
    fn from(caps: u32) -> Self {
        let widget_type = NodeType::from(((caps >> 20) & 0x0F) as u8);
        Self {
            widget_type,
            conn_list: (caps & (1 << 8)) != 0,
            out_amp: (caps & (1 << 2)) != 0,
            in_amp: (caps & (1 << 1)) != 0,
            format_override: (caps & (1 << 4)) != 0,
            stereo: (caps & (1 << 0)) != 0,
        }
    }
}

/// Codec information
#[derive(Debug, Clone)]
pub struct CodecInfo {
    /// Codec address (0-14)
    pub address: u8,
    /// Vendor ID
    pub vendor_id: u16,
    /// Device ID
    pub device_id: u16,
    /// Revision ID
    pub revision: u8,
    /// Audio Function Group node ID
    pub afg_node: Option<u8>,
    /// Output converter nodes
    pub output_nodes: Vec<u8>,
    /// Input converter nodes
    pub input_nodes: Vec<u8>,
    /// Pin complex nodes
    pub pin_nodes: Vec<u8>,
    /// Beep generator node
    pub beep_node: Option<u8>,
}

// ============================================================================
// HDA Controller
// ============================================================================

/// Intel HD Audio Controller
pub struct HdaController {
    /// PCI device info
    pci_device: PciDevice,
    /// Memory-mapped register base address
    mmio_base: u64,
    /// CORB buffer (physical address)
    corb_addr: u64,
    /// CORB buffer size
    corb_size: usize,
    /// CORB write pointer
    corb_wp: AtomicU16,
    /// RIRB buffer (physical address)
    rirb_addr: u64,
    /// RIRB buffer size
    rirb_size: usize,
    /// RIRB read pointer
    rirb_rp: AtomicU16,
    /// Detected codecs
    codecs: Vec<CodecInfo>,
    /// Number of input streams
    num_input_streams: u32,
    /// Number of output streams
    num_output_streams: u32,
    /// Number of bidirectional streams
    num_bidir_streams: u32,
    /// Controller initialized flag
    initialized: AtomicBool,
    /// DMA position buffer address
    dma_pos_addr: u64,
    /// Stream BDL addresses
    stream_bdl_addrs: [u64; 8],
    /// Audio data buffers
    audio_buffers: [u64; 8],
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
    fn new(pci_device: PciDevice, mmio_base: u64) -> Self {
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
    fn read8(&self, offset: u32) -> u8 {
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
    fn write8(&self, offset: u32, value: u8) {
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
    fn read16(&self, offset: u32) -> u16 {
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
    fn write16(&self, offset: u32, value: u16) {
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
    fn read32(&self, offset: u32) -> u32 {
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
    fn write32(&self, offset: u32, value: u32) {
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
    fn alloc_dma_buffer(size: usize) -> HdaResult<u64> {
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
        crate::io::dma_cache::sfence();

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
                crate::io::dma_cache::lfence();

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
    // Codec Detection and Initialization
    // ========================================================================

    /// Detect connected codecs
    fn detect_codecs(&mut self) -> HdaResult<()> {
        crate::log!("[HDA] Detecting codecs...\n");

        let statests = self.read16(REG_STATESTS);

        for codec_addr in 0..15 {
            if (statests & (1 << codec_addr)) != 0 {
                crate::log!("[HDA] Codec found at address {}\n", codec_addr);

                // Read vendor/device ID
                let vendor_id = self.get_parameter(codec_addr as u8, 0, PARAM_VENDOR_ID)?;
                let vendor = (vendor_id >> 16) as u16;
                let device = vendor_id as u16;

                crate::log!(
                    "[HDA] Codec {}: Vendor={:04x}, Device={:04x}\n",
                    codec_addr,
                    vendor,
                    device
                );

                let codec = CodecInfo {
                    address: codec_addr as u8,
                    vendor_id: vendor,
                    device_id: device,
                    revision: 0,
                    afg_node: None,
                    output_nodes: Vec::new(),
                    input_nodes: Vec::new(),
                    pin_nodes: Vec::new(),
                    beep_node: None,
                };

                self.codecs.push(codec);
            }
        }

        if self.codecs.is_empty() {
            return Err(HdaError::NoCodec);
        }

        // Clear state change status
        self.write16(REG_STATESTS, statests);

        Ok(())
    }

    /// Initialize detected codecs
    fn init_codecs(&mut self) -> HdaResult<()> {
        for i in 0..self.codecs.len() {
            let codec_addr = self.codecs[i].address;
            self.enumerate_codec(codec_addr)?;
        }

        Ok(())
    }

    /// Enumerate codec nodes
    fn enumerate_codec(&mut self, codec_addr: u8) -> HdaResult<()> {
        crate::log!("[HDA] Enumerating codec {}...\n", codec_addr);

        // Get subordinate node count from root node (node 0)
        let sub_nodes = self.get_parameter(codec_addr, 0, PARAM_SUB_NODE_COUNT)?;
        let start_node = ((sub_nodes >> 16) & 0xFF) as u8;
        let num_nodes = (sub_nodes & 0xFF) as u8;

        crate::log!(
            "[HDA] Root node: start={}, count={}\n",
            start_node,
            num_nodes
        );

        // Look for Audio Function Group
        for node_id in start_node..(start_node + num_nodes) {
            let func_type = self.get_parameter(codec_addr, node_id, PARAM_FUNC_GROUP_TYPE)?;
            let node_type = func_type & 0xFF;

            crate::log!(
                "[HDA] Node {}: type={}\n",
                node_id,
                if node_type == 1 { "AFG" } else { "other" }
            );

            if node_type == 0x01 {
                // Audio Function Group
                // Find codec in our list
                if let Some(codec) = self.codecs.iter_mut().find(|c| c.address == codec_addr) {
                    codec.afg_node = Some(node_id);
                }

                // Enumerate AFG sub-nodes
                self.enumerate_afg(codec_addr, node_id)?;
            }
        }

        Ok(())
    }

    /// Enumerate Audio Function Group nodes
    fn enumerate_afg(&mut self, codec_addr: u8, afg_node: u8) -> HdaResult<()> {
        // Power up the AFG
        self.send_command(codec_addr, afg_node, VERB_SET_POWER | POWER_D0 as u32)?;
        Self::delay_us(10000); // Wait for power up

        // Get subordinate nodes
        let sub_nodes = self.get_parameter(codec_addr, afg_node, PARAM_SUB_NODE_COUNT)?;
        let start_node = ((sub_nodes >> 16) & 0xFF) as u8;
        let num_nodes = (sub_nodes & 0xFF) as u8;

        crate::log!(
            "[HDA] AFG {}: widgets {}..{}\n",
            afg_node,
            start_node,
            start_node + num_nodes - 1
        );

        for node_id in start_node..(start_node + num_nodes) {
            let caps = self.get_parameter(codec_addr, node_id, PARAM_WIDGET_CAPS)?;
            let widget_caps = WidgetCaps::from(caps);

            crate::log!(
                "[HDA] Widget {}: {:?}\n",
                node_id,
                widget_caps.widget_type
            );

            // Find codec and add node to appropriate list
            if let Some(codec) = self.codecs.iter_mut().find(|c| c.address == codec_addr) {
                match widget_caps.widget_type {
                    NodeType::AudioOutput => codec.output_nodes.push(node_id),
                    NodeType::AudioInput => codec.input_nodes.push(node_id),
                    NodeType::PinComplex => codec.pin_nodes.push(node_id),
                    NodeType::BeepGenerator => codec.beep_node = Some(node_id),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    // ========================================================================
    // Audio Output
    // ========================================================================

    /// Configure an output stream for playback
    pub fn setup_output_stream(
        &mut self,
        stream_index: u32,
        sample_rate: u32,
        bits: u8,
        channels: u8,
    ) -> HdaResult<()> {
        if stream_index >= self.num_output_streams {
            return Err(HdaError::StreamError("Invalid stream index".into()));
        }

        let stream_base = stream_offset(true, self.num_input_streams, stream_index);

        crate::log!(
            "[HDA] Setting up output stream {} at offset 0x{:x}\n",
            stream_index,
            stream_base
        );

        // Reset stream
        self.write8(stream_base + REG_SD_CTL0, SD_CTL0_SRST);
        Self::delay_us(1000);

        // Wait for reset to complete
        let mut timeout = 1000;
        while timeout > 0 {
            if (self.read8(stream_base + REG_SD_CTL0) & SD_CTL0_SRST) != 0 {
                break;
            }
            Self::delay_us(10);
            timeout -= 1;
        }

        // Clear reset
        self.write8(stream_base + REG_SD_CTL0, 0);
        timeout = 1000;
        while timeout > 0 {
            if (self.read8(stream_base + REG_SD_CTL0) & SD_CTL0_SRST) == 0 {
                break;
            }
            Self::delay_us(10);
            timeout -= 1;
        }

        // Calculate format
        let format = self.calculate_stream_format(sample_rate, bits, channels);
        crate::log!("[HDA] Stream format: 0x{:04x}\n", format);

        // Set stream format
        self.write16(stream_base + REG_SD_FMT, format);

        // Set stream number (1-15, stream 0 is reserved)
        let stream_num = (stream_index + 1) as u8;
        self.write8(
            stream_base + REG_SD_CTL2,
            (stream_num << SD_CTL2_STRM_SHIFT) & SD_CTL2_STRM_MASK,
        );

        Ok(())
    }

    /// Calculate stream format register value
    fn calculate_stream_format(&self, sample_rate: u32, bits: u8, channels: u8) -> u16 {
        let mut format: u16 = 0;

        // Channels (0 = 1 channel, 1 = 2 channels, etc.)
        format |= (channels - 1) as u16 & FMT_CHAN_MASK;

        // Bits per sample
        format |= match bits {
            8 => FMT_BITS_8,
            16 => FMT_BITS_16,
            20 => FMT_BITS_20,
            24 => FMT_BITS_24,
            32 => FMT_BITS_32,
            _ => FMT_BITS_16,
        };

        // Sample rate (base + multiplier + divisor)
        // Base: 48kHz = 0, 44.1kHz = 1
        // For 48kHz: mult=0, div=0
        match sample_rate {
            48000 => {} // Base 48kHz, no mult/div
            44100 => format |= FMT_BASE,
            96000 => format |= (1 << FMT_MULT_SHIFT), // 48kHz * 2
            192000 => format |= (3 << FMT_MULT_SHIFT), // 48kHz * 4
            _ => {} // Default to 48kHz
        }

        format
    }

    /// Setup Buffer Descriptor List for a stream
    pub fn setup_bdl(
        &mut self,
        stream_index: u32,
        buffer_addr: u64,
        buffer_size: u32,
        num_entries: u32,
    ) -> HdaResult<()> {
        if stream_index >= self.num_output_streams {
            return Err(HdaError::StreamError("Invalid stream index".into()));
        }

        let stream_base = stream_offset(true, self.num_input_streams, stream_index);

        // Allocate BDL
        let bdl_size = (num_entries as usize) * BDL_ENTRY_SIZE;
        let bdl_addr = Self::alloc_dma_buffer(bdl_size)?;
        self.stream_bdl_addrs[stream_index as usize] = bdl_addr;

        // Fill BDL entries
        let segment_size = buffer_size / num_entries;
        for i in 0..num_entries {
            let entry_addr = bdl_addr + (i as u64 * BDL_ENTRY_SIZE as u64);
            let buf_offset = buffer_addr + (i as u64 * segment_size as u64);

            let entry = BdlEntry::new(buf_offset, segment_size, i == num_entries - 1);

            // SAFETY: entry_addr points to a valid DMA buffer allocated by alloc_dma_buffer.
            // BdlEntry is repr(C, align(16)) ensuring proper alignment.
            // The write is within bounds (i < num_entries).
            unsafe {
                write_volatile(entry_addr as *mut BdlEntry, entry);
            }
        }

        // SAFETY: SFENCE ensures all BDL entries are visible to the HDA controller
        // before we configure the stream to use this BDL.
        crate::io::dma_cache::sfence();

        // Set BDL address
        self.write32(stream_base + REG_SD_BDPL, bdl_addr as u32);
        self.write32(stream_base + REG_SD_BDPU, (bdl_addr >> 32) as u32);

        // Set cyclic buffer length
        self.write32(stream_base + REG_SD_CBL, buffer_size);

        // Set last valid index
        self.write16(stream_base + REG_SD_LVI, (num_entries - 1) as u16);

        crate::log!(
            "[HDA] BDL configured: {} entries, {} bytes total\n",
            num_entries,
            buffer_size
        );

        Ok(())
    }

    /// Start stream playback
    pub fn start_stream(&self, stream_index: u32) -> HdaResult<()> {
        if stream_index >= self.num_output_streams {
            return Err(HdaError::StreamError("Invalid stream index".into()));
        }

        let stream_base = stream_offset(true, self.num_input_streams, stream_index);

        // Enable stream run and interrupts
        self.write8(
            stream_base + REG_SD_CTL0,
            SD_CTL0_RUN | SD_CTL0_IOCE | SD_CTL0_FEIE | SD_CTL0_DEIE,
        );

        // Enable stream interrupt
        let intctl = self.read32(REG_INTCTL);
        self.write32(
            REG_INTCTL,
            intctl | (1 << (self.num_input_streams + stream_index)),
        );

        crate::log!("[HDA] Stream {} started\n", stream_index);
        Ok(())
    }

    /// Stop stream playback
    pub fn stop_stream(&self, stream_index: u32) -> HdaResult<()> {
        if stream_index >= self.num_output_streams {
            return Err(HdaError::StreamError("Invalid stream index".into()));
        }

        let stream_base = stream_offset(true, self.num_input_streams, stream_index);

        // Disable stream run
        self.write8(stream_base + REG_SD_CTL0, 0);

        crate::log!("[HDA] Stream {} stopped\n", stream_index);
        Ok(())
    }

    // ========================================================================
    // Codec Output Configuration
    // ========================================================================

    /// Configure codec for audio output
    pub fn configure_codec_output(&self, codec_addr: u8, stream_num: u8) -> HdaResult<()> {
        let codec = self
            .codecs
            .iter()
            .find(|c| c.address == codec_addr)
            .ok_or(HdaError::NoCodec)?;

        // Find an output DAC
        let dac_node = codec.output_nodes.first().copied().ok_or_else(|| {
            HdaError::InitFailed("No DAC found".into())
        })?;

        // Find an output pin
        let pin_node = codec.pin_nodes.first().copied().ok_or_else(|| {
            HdaError::InitFailed("No output pin found".into())
        })?;

        crate::log!(
            "[HDA] Configuring DAC {} -> Pin {} for stream {}\n",
            dac_node,
            pin_node,
            stream_num
        );

        // Power up DAC
        self.send_command(codec_addr, dac_node, VERB_SET_POWER | POWER_D0 as u32)?;
        Self::delay_us(1000);

        // Set stream/channel assignment
        // Stream number in upper 4 bits, channel in lower 4 bits
        let stream_chan = ((stream_num as u32) << 4) | 0; // Stream N, Channel 0
        self.send_command(codec_addr, dac_node, VERB_SET_CONV_STREAM | stream_chan)?;

        // Set converter format (48kHz, 16-bit, stereo)
        let format = 0x0011; // 48kHz, 16-bit, 2 channels
        self.send_command(codec_addr, dac_node, VERB_SET_CONV_FMT | format)?;

        // Unmute DAC output amplifier
        let amp_val = AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | 0x7F; // Max gain
        self.send_command(codec_addr, dac_node, VERB_SET_AMP_GAIN | amp_val as u32)?;

        // Power up pin
        self.send_command(codec_addr, pin_node, VERB_SET_POWER | POWER_D0 as u32)?;
        Self::delay_us(1000);

        // Enable pin output
        self.send_command(
            codec_addr,
            pin_node,
            VERB_SET_PIN_CTL | PIN_CTL_OUT_EN as u32,
        )?;

        // Enable EAPD if available (for external amplifier)
        self.send_command(codec_addr, pin_node, VERB_SET_EAPD | EAPD_EAPD as u32)?;

        // Unmute pin output amplifier
        self.send_command(codec_addr, pin_node, VERB_SET_AMP_GAIN | amp_val as u32)?;

        crate::log!("[HDA] Codec output configured\n");
        Ok(())
    }

    // ========================================================================
    // Beep Generation
    // ========================================================================

    /// Play a beep tone using the codec's beep generator
    pub fn beep(&self, codec_addr: u8, frequency_divisor: u8) -> HdaResult<()> {
        let codec = self
            .codecs
            .iter()
            .find(|c| c.address == codec_addr)
            .ok_or(HdaError::NoCodec)?;

        let beep_node = codec.beep_node.ok_or_else(|| {
            HdaError::InitFailed("No beep generator found".into())
        })?;

        crate::log!(
            "[HDA] Beep: codec={}, node={}, div={}\n",
            codec_addr,
            beep_node,
            frequency_divisor
        );

        // Power up beep generator
        self.send_command(codec_addr, beep_node, VERB_SET_POWER | POWER_D0 as u32)?;
        Self::delay_us(1000);

        // Set beep frequency
        // Frequency = 48000 / (N * 4) Hz
        // N = frequency_divisor
        self.send_command(
            codec_addr,
            beep_node,
            VERB_SET_BEEP | frequency_divisor as u32,
        )?;

        Ok(())
    }

    /// Stop the beep tone
    pub fn beep_stop(&self, codec_addr: u8) -> HdaResult<()> {
        let codec = self
            .codecs
            .iter()
            .find(|c| c.address == codec_addr)
            .ok_or(HdaError::NoCodec)?;

        if let Some(beep_node) = codec.beep_node {
            self.send_command(codec_addr, beep_node, VERB_SET_BEEP | BEEP_OFF as u32)?;
        }

        Ok(())
    }

    /// Play a beep for a specified duration (blocking)
    pub fn beep_duration(&self, codec_addr: u8, frequency_hz: u32, duration_ms: u32) -> HdaResult<()> {
        // Calculate frequency divisor: N = 48000 / (freq * 4)
        let divisor = if frequency_hz > 0 {
            (48000 / (frequency_hz * 4)).clamp(1, 255) as u8
        } else {
            60 // Default ~200Hz
        };

        self.beep(codec_addr, divisor)?;
        Self::delay_us(duration_ms as u64 * 1000);
        self.beep_stop(codec_addr)?;

        Ok(())
    }

    // ========================================================================
    // Square Wave Generation (Software-based)
    // ========================================================================

    /// Generate a square wave audio buffer
    pub fn generate_square_wave(
        buffer: &mut [i16],
        frequency: u32,
        sample_rate: u32,
        amplitude: i16,
    ) {
        let samples_per_period = sample_rate / frequency;
        let half_period = samples_per_period / 2;

        for (i, sample) in buffer.iter_mut().enumerate() {
            let pos = i as u32 % samples_per_period;
            *sample = if pos < half_period {
                amplitude
            } else {
                -amplitude
            };
        }
    }

    /// Play a square wave beep using stream output
    pub fn play_square_wave(
        &mut self,
        frequency: u32,
        duration_ms: u32,
    ) -> HdaResult<()> {
        const SAMPLE_RATE: u32 = 48000;
        const BITS: u8 = 16;
        const CHANNELS: u8 = 2;

        if self.codecs.is_empty() {
            return Err(HdaError::NoCodec);
        }

        let codec_addr = self.codecs[0].address;

        // Calculate buffer size for duration
        let samples = (SAMPLE_RATE * duration_ms / 1000) as usize;
        let buffer_size = samples * (BITS as usize / 8) * CHANNELS as usize;

        // Allocate audio buffer
        let audio_buffer_addr = Self::alloc_dma_buffer(buffer_size)?;
        self.audio_buffers[0] = audio_buffer_addr;

        // Generate square wave
        // SAFETY: audio_buffer_addr points to a valid DMA buffer allocated by alloc_dma_buffer.
        // The buffer size is samples * 2 * sizeof(i16) = buffer_size bytes.
        // We create a mutable slice of samples * 2 i16 values (stereo: L, R pairs).
        let buffer_slice =
            unsafe { core::slice::from_raw_parts_mut(audio_buffer_addr as *mut i16, samples * 2) };

        // Generate mono wave, then copy to stereo
        let mono_buffer: Vec<i16> = (0..samples)
            .map(|i| {
                let samples_per_period = SAMPLE_RATE / frequency;
                let half_period = samples_per_period / 2;
                let pos = i as u32 % samples_per_period;
                if pos < half_period { 16000i16 } else { -16000i16 }
            })
            .collect();

        // Copy to stereo buffer (L, R, L, R, ...)
        for (i, &sample) in mono_buffer.iter().enumerate() {
            buffer_slice[i * 2] = sample; // Left
            buffer_slice[i * 2 + 1] = sample; // Right
        }

        // Setup output stream
        self.setup_output_stream(0, SAMPLE_RATE, BITS, CHANNELS)?;

        // Setup BDL
        self.setup_bdl(0, audio_buffer_addr, buffer_size as u32, 4)?;

        // Configure codec
        self.configure_codec_output(codec_addr, 1)?;

        // Start playback
        self.start_stream(0)?;

        // Wait for playback to complete
        Self::delay_us(duration_ms as u64 * 1000 + 100000);

        // Stop playback
        self.stop_stream(0)?;

        crate::log!("[HDA] Square wave playback complete\n");
        Ok(())
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /// Microsecond delay (PIT タイマーベース)
    ///
    /// 従来の spin_loop による空回しから PIT ワンショットモードに変更。
    /// より正確な時間待機が可能になる。
    fn delay_us(us: u64) {
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

// ============================================================================
// Global HDA Driver Instance
// ============================================================================

static HDA_DRIVER: Mutex<Option<HdaController>> = Mutex::new(None);

/// Initialize the HDA driver
pub fn init() -> HdaResult<()> {
    crate::log!("[HDA] Searching for Intel HD Audio device...\n");

    // Search for HDA device (class 04, subclass 03)
    let devices = find_by_class(HDA_CLASS, HDA_SUBCLASS);

    if devices.is_empty() {
        crate::log!("[HDA] No HD Audio device found\n");
        return Err(HdaError::NoDevice);
    }

    let pci_device = devices.into_iter().next().unwrap();

    crate::log!(
        "[HDA] Found device: {:04x}:{:04x} at {:02x}:{:02x}.{}\n",
        pci_device.vendor_id,
        pci_device.device_id,
        pci_device.bus,
        pci_device.device,
        pci_device.function
    );

    // PCI 割り込みライン（IRQ）を保存
    let irq = pci_device.interrupt_line;
    if irq > 0 && irq < 16 {
        HDA_IRQ.store(irq, Ordering::SeqCst);
        crate::log!("[HDA] IRQ: {} (interrupt_pin: {})\n", irq, pci_device.interrupt_pin);
    } else {
        crate::log!("[HDA] Warning: Invalid IRQ {} (will use polling mode)\n", irq);
    }

    // Get BAR0 (MMIO)
    let mmio_base = match pci_device.bars[0] {
        PciBar::Memory { address, .. } => address,
        _ => return Err(HdaError::InvalidBar),
    };

    crate::log!("[HDA] MMIO base: 0x{:016x}\n", mmio_base);

    // Create and initialize controller
    let mut controller = HdaController::new(pci_device, mmio_base);
    controller.init()?;

    *HDA_DRIVER.lock() = Some(controller);

    Ok(())
}

/// Access the HDA driver
pub fn with_driver<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&HdaController) -> R,
{
    HDA_DRIVER.lock().as_ref().map(f)
}

/// Access the HDA driver mutably
pub fn with_driver_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut HdaController) -> R,
{
    HDA_DRIVER.lock().as_mut().map(f)
}

/// Play a beep using the codec's beep generator
pub fn beep(frequency_hz: u32, duration_ms: u32) -> HdaResult<()> {
    let mut driver = HDA_DRIVER.lock();
    let driver = driver.as_ref().ok_or(HdaError::NoDevice)?;

    if driver.codecs.is_empty() {
        return Err(HdaError::NoCodec);
    }

    driver.beep_duration(driver.codecs[0].address, frequency_hz, duration_ms)
}

/// Play a square wave tone
pub fn play_tone(frequency_hz: u32, duration_ms: u32) -> HdaResult<()> {
    let mut driver = HDA_DRIVER.lock();
    let driver = driver.as_mut().ok_or(HdaError::NoDevice)?;

    driver.play_square_wave(frequency_hz, duration_ms)
}

/// Quick test: play a startup beep sequence
pub fn test_beep() -> HdaResult<()> {
    crate::log!("[HDA] Playing test beep sequence...\n");

    // Try beep generator first
    if beep(440, 200).is_ok() {
        HdaController::delay_us(100000);
        beep(880, 200)?;
        HdaController::delay_us(100000);
        beep(440, 400)?;
        return Ok(());
    }

    // Fall back to square wave if no beep generator
    play_tone(440, 200)?;
    HdaController::delay_us(100000);
    play_tone(880, 200)?;
    HdaController::delay_us(100000);
    play_tone(440, 400)?;

    Ok(())
}

// ============================================================================
// HDA Interrupt Handler
// ============================================================================

/// HDA 割り込みハンドラ
///
/// この関数は IDT から呼び出される。
/// 割り込みステータスをクリアし、必要に応じて待機中のタスクを起床させる。
pub fn handle_interrupt() {
    let count = HDA_INTERRUPT_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    
    // コントローラーの割り込みステータスを読み取り・クリア
    if let Some(driver) = HDA_DRIVER.lock().as_ref() {
        // INTSTS レジスタを読み取り
        let intsts = driver.read32(REG_INTSTS);
        
        if intsts != 0 {
            // ストリーム完了割り込みの処理
            if intsts & INTSTS_SIS_MASK != 0 {
                // 各ストリームの割り込みを確認
                for stream in 0..8u32 {
                    if intsts & (1 << stream) != 0 {
                        // ストリームステータスレジスタをクリア
                        // (ストリーム N のステータスは offset 0x80 + N*0x20 + 0x03)
                        let stream_offset = 0x80 + stream * 0x20;
                        let sts = driver.read8(stream_offset + 0x03);
                        driver.write8(stream_offset + 0x03, sts); // Write-1-to-clear
                    }
                }
            }
            
            // Controller Interrupt Status をクリア (Write-1-to-clear)
            driver.write32(REG_INTSTS, intsts);
            
            // ペンディングフラグを設定
            HDA_INTERRUPT_PENDING.store(true, Ordering::SeqCst);
        }
    }

    // Interrupt-Waker ブリッジに通知（オーディオ待機中のタスクを起床）
    // HDA の IRQ 番号を使用して汎用 Irq ソースとして通知
    let irq = HDA_IRQ.load(Ordering::SeqCst);
    interrupt_waker::wake_from_interrupt(interrupt_waker::InterruptSource::Irq(irq));

    // デバッグ出力（最初の数回のみ）
    if count < 5 {
        crate::log!("[HDA] Interrupt #{}\n", count);
    }
}

/// HDA で使用する IRQ 番号を取得
pub fn get_irq() -> u8 {
    HDA_IRQ.load(Ordering::SeqCst)
}

/// 割り込みペンディングフラグをクリアして状態を返す
pub fn clear_interrupt_pending() -> bool {
    HDA_INTERRUPT_PENDING.swap(false, Ordering::SeqCst)
}

/// 割り込み発生回数を取得
pub fn get_interrupt_count() -> u64 {
    HDA_INTERRUPT_COUNT.load(Ordering::SeqCst)
}

/// HDA 割り込みをアンマスク（有効化）
pub fn enable_irq() {
    let irq = HDA_IRQ.load(Ordering::SeqCst);
    if irq > 0 && irq < 16 {
        crate::interrupts::unmask_irq(irq);
        crate::log!("[HDA] IRQ {} unmasked\n", irq);
    }
}

/// HDA 割り込みをマスク（無効化）
pub fn disable_irq() {
    let irq = HDA_IRQ.load(Ordering::SeqCst);
    if irq > 0 && irq < 16 {
        crate::interrupts::mask_irq(irq);
        crate::log!("[HDA] IRQ {} masked\n", irq);
    }
}
