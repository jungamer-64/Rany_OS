// ============================================================================
// src/io/audio/regs.rs - Intel High Definition Audio Register Definitions
// ============================================================================
//!
//! # Intel HD Audio レジスタ定義
//!
//! Intel High Definition Audio Specification Rev 1.0a に基づくレジスタ定義。
//! QEMUの intel-hda デバイスと互換性あり。

#![allow(dead_code)]

// ============================================================================
// PCI Configuration Space
// ============================================================================

/// Intel HD Audio Vendor ID
pub const HDA_VENDOR_INTEL: u16 = 0x8086;

/// QEMU HDA Device ID (intel-hda)
pub const HDA_DEVICE_QEMU: u16 = 0x2668;

/// HDA Controller Class Code (Multimedia / HD Audio)
pub const HDA_CLASS: u8 = 0x04;
pub const HDA_SUBCLASS: u8 = 0x03;

// ============================================================================
// Global Registers (Offset 0x00 - 0x2F)
// ============================================================================

/// Global Capabilities (GCAP) - 16-bit, RO
/// Offset: 0x00
pub const REG_GCAP: u32 = 0x00;

/// Minor Version (VMIN) - 8-bit, RO
/// Offset: 0x02
pub const REG_VMIN: u32 = 0x02;

/// Major Version (VMAJ) - 8-bit, RO
/// Offset: 0x03
pub const REG_VMAJ: u32 = 0x03;

/// Output Payload Capability (OUTPAY) - 16-bit, RO
/// Offset: 0x04
pub const REG_OUTPAY: u32 = 0x04;

/// Input Payload Capability (INPAY) - 16-bit, RO
/// Offset: 0x06
pub const REG_INPAY: u32 = 0x06;

/// Global Control (GCTL) - 32-bit, RW
/// Offset: 0x08
pub const REG_GCTL: u32 = 0x08;

/// Wake Enable (WAKEEN) - 16-bit, RW
/// Offset: 0x0C
pub const REG_WAKEEN: u32 = 0x0C;

/// State Change Status (STATESTS) - 16-bit, RW1C
/// Offset: 0x0E
pub const REG_STATESTS: u32 = 0x0E;

/// Global Status (GSTS) - 16-bit, RO
/// Offset: 0x10
pub const REG_GSTS: u32 = 0x10;

/// Output Stream Payload Capability (OUTSTRMPAY) - 16-bit, RO
/// Offset: 0x18
pub const REG_OUTSTRMPAY: u32 = 0x18;

/// Input Stream Payload Capability (INSTRMPAY) - 16-bit, RO
/// Offset: 0x1A
pub const REG_INSTRMPAY: u32 = 0x1A;

/// Interrupt Control (INTCTL) - 32-bit, RW
/// Offset: 0x20
pub const REG_INTCTL: u32 = 0x20;

/// Interrupt Status (INTSTS) - 32-bit, RO/RW1C
/// Offset: 0x24
pub const REG_INTSTS: u32 = 0x24;

/// Wall Clock Counter (WALCLK) - 32-bit, RO
/// Offset: 0x30
pub const REG_WALCLK: u32 = 0x30;

/// Stream Synchronization (SSYNC) - 32-bit, RW
/// Offset: 0x38
pub const REG_SSYNC: u32 = 0x38;

// ============================================================================
// GCTL (Global Control) Bit Definitions
// ============================================================================

/// Controller Reset (CRST) - Bit 0
/// 0 = Controller in reset, 1 = Controller running
pub const GCTL_CRST: u32 = 1 << 0;

/// Flush Control (FCNTRL) - Bit 1
pub const GCTL_FCNTRL: u32 = 1 << 1;

/// Accept Unsolicited Response Enable (UNSOL) - Bit 8
pub const GCTL_UNSOL: u32 = 1 << 8;

// ============================================================================
// INTCTL (Interrupt Control) Bit Definitions
// ============================================================================

/// Stream Interrupt Enable bits (bit 0-29)
pub const INTCTL_SIE_MASK: u32 = 0x3FFFFFFF;

/// Controller Interrupt Enable (CIE) - Bit 30
pub const INTCTL_CIE: u32 = 1 << 30;

/// Global Interrupt Enable (GIE) - Bit 31
pub const INTCTL_GIE: u32 = 1 << 31;

// ============================================================================
// INTSTS (Interrupt Status) Bit Definitions
// ============================================================================

/// Stream Interrupt Status bits (bit 0-29)
pub const INTSTS_SIS_MASK: u32 = 0x3FFFFFFF;

/// Controller Interrupt Status (CIS) - Bit 30
pub const INTSTS_CIS: u32 = 1 << 30;

/// Global Interrupt Status (GIS) - Bit 31
pub const INTSTS_GIS: u32 = 1 << 31;

// ============================================================================
// CORB Registers (Offset 0x40 - 0x4F)
// ============================================================================

/// CORB Lower Base Address (CORBLBASE) - 32-bit, RW
/// Offset: 0x40
pub const REG_CORBLBASE: u32 = 0x40;

/// CORB Upper Base Address (CORBUBASE) - 32-bit, RW
/// Offset: 0x44
pub const REG_CORBUBASE: u32 = 0x44;

/// CORB Write Pointer (CORBWP) - 16-bit, RW
/// Offset: 0x48
pub const REG_CORBWP: u32 = 0x48;

/// CORB Read Pointer (CORBRP) - 16-bit, RW/RO
/// Offset: 0x4A
pub const REG_CORBRP: u32 = 0x4A;

/// CORB Control (CORBCTL) - 8-bit, RW
/// Offset: 0x4C
pub const REG_CORBCTL: u32 = 0x4C;

/// CORB Status (CORBSTS) - 8-bit, RW1C
/// Offset: 0x4D
pub const REG_CORBSTS: u32 = 0x4D;

/// CORB Size (CORBSIZE) - 8-bit, RW
/// Offset: 0x4E
pub const REG_CORBSIZE: u32 = 0x4E;

// ============================================================================
// CORBCTL (CORB Control) Bit Definitions
// ============================================================================

/// CORB Memory Error Interrupt Enable (CMEIE) - Bit 0
pub const CORBCTL_CMEIE: u8 = 1 << 0;

/// CORB DMA Enable (CORBRUN) - Bit 1
pub const CORBCTL_CORBRUN: u8 = 1 << 1;

// ============================================================================
// CORBSTS (CORB Status) Bit Definitions
// ============================================================================

/// CORB Memory Error Indication (CMEI) - Bit 0
pub const CORBSTS_CMEI: u8 = 1 << 0;

// ============================================================================
// CORBRP (CORB Read Pointer) Bit Definitions
// ============================================================================

/// CORB Read Pointer Reset (CORBRPRST) - Bit 15
pub const CORBRP_RST: u16 = 1 << 15;

// ============================================================================
// CORBSIZE Bit Definitions
// ============================================================================

/// CORB Size Capability (CORBSZCAP) - Bits 4-7
pub const CORBSIZE_SZCAP_SHIFT: u8 = 4;
pub const CORBSIZE_SZCAP_MASK: u8 = 0xF0;

/// CORB Size (CORBSIZE) - Bits 0-1
pub const CORBSIZE_SIZE_MASK: u8 = 0x03;

/// CORB Size: 2 entries
pub const CORBSIZE_2: u8 = 0x00;
/// CORB Size: 16 entries
pub const CORBSIZE_16: u8 = 0x01;
/// CORB Size: 256 entries
pub const CORBSIZE_256: u8 = 0x02;

// ============================================================================
// RIRB Registers (Offset 0x50 - 0x5F)
// ============================================================================

/// RIRB Lower Base Address (RIRBLBASE) - 32-bit, RW
/// Offset: 0x50
pub const REG_RIRBLBASE: u32 = 0x50;

/// RIRB Upper Base Address (RIRBUBASE) - 32-bit, RW
/// Offset: 0x54
pub const REG_RIRBUBASE: u32 = 0x54;

/// RIRB Write Pointer (RIRBWP) - 16-bit, RO
/// Offset: 0x58
pub const REG_RIRBWP: u32 = 0x58;

/// Response Interrupt Count (RINTCNT) - 16-bit, RW
/// Offset: 0x5A
pub const REG_RINTCNT: u32 = 0x5A;

/// RIRB Control (RIRBCTL) - 8-bit, RW
/// Offset: 0x5C
pub const REG_RIRBCTL: u32 = 0x5C;

/// RIRB Status (RIRBSTS) - 8-bit, RW1C
/// Offset: 0x5D
pub const REG_RIRBSTS: u32 = 0x5D;

/// RIRB Size (RIRBSIZE) - 8-bit, RW
/// Offset: 0x5E
pub const REG_RIRBSIZE: u32 = 0x5E;

// ============================================================================
// RIRBWP (RIRB Write Pointer) Bit Definitions
// ============================================================================

/// RIRB Write Pointer Reset (RIRBWPRST) - Bit 15
pub const RIRBWP_RST: u16 = 1 << 15;

// ============================================================================
// RIRBCTL (RIRB Control) Bit Definitions
// ============================================================================

/// Response Interrupt Control (RINTCTL) - Bit 0
pub const RIRBCTL_RINTCTL: u8 = 1 << 0;

/// RIRB DMA Enable (RIRBDMAEN) - Bit 1
pub const RIRBCTL_DMAEN: u8 = 1 << 1;

/// Response Overrun Interrupt Control (RIRBOIC) - Bit 2
pub const RIRBCTL_OIC: u8 = 1 << 2;

// ============================================================================
// RIRBSTS (RIRB Status) Bit Definitions
// ============================================================================

/// Response Interrupt (RINTFL) - Bit 0
pub const RIRBSTS_RINTFL: u8 = 1 << 0;

/// Response Overrun Interrupt Status (RIRBOIS) - Bit 2
pub const RIRBSTS_OIS: u8 = 1 << 2;

// ============================================================================
// RIRBSIZE Bit Definitions
// ============================================================================

/// RIRB Size Capability (RIRBSZCAP) - Bits 4-7
pub const RIRBSIZE_SZCAP_SHIFT: u8 = 4;
pub const RIRBSIZE_SZCAP_MASK: u8 = 0xF0;

/// RIRB Size (RIRBSIZE) - Bits 0-1
pub const RIRBSIZE_SIZE_MASK: u8 = 0x03;

/// RIRB Size: 2 entries
pub const RIRBSIZE_2: u8 = 0x00;
/// RIRB Size: 16 entries
pub const RIRBSIZE_16: u8 = 0x01;
/// RIRB Size: 256 entries
pub const RIRBSIZE_256: u8 = 0x02;

// ============================================================================
// Immediate Command Registers (Offset 0x60 - 0x6F)
// ============================================================================

/// Immediate Command Output Interface (ICS) - 32-bit, RW
/// Offset: 0x60
pub const REG_ICO: u32 = 0x60;

/// Immediate Response Input Interface (IRI) - 32-bit, RO
/// Offset: 0x64
pub const REG_IRI: u32 = 0x64;

/// Immediate Command Status (ICS) - 16-bit, RW1C/RO
/// Offset: 0x68
pub const REG_ICS: u32 = 0x68;

// ============================================================================
// ICS (Immediate Command Status) Bit Definitions
// ============================================================================

/// Immediate Command Busy (ICB) - Bit 0
pub const ICS_ICB: u16 = 1 << 0;

/// Immediate Result Valid (IRV) - Bit 1
pub const ICS_IRV: u16 = 1 << 1;

// ============================================================================
// DMA Position Buffer
// ============================================================================

/// DMA Position Lower Base Address (DPLBASE) - 32-bit, RW
/// Offset: 0x70
pub const REG_DPLBASE: u32 = 0x70;

/// DMA Position Upper Base Address (DPUBASE) - 32-bit, RW
/// Offset: 0x74
pub const REG_DPUBASE: u32 = 0x74;

/// DMA Position Buffer Enable (DPBE) - Bit 0 of DPLBASE
pub const DPLBASE_DPBE: u32 = 1 << 0;

// ============================================================================
// Stream Descriptor Registers (Relative to stream base)
// ============================================================================

/// Stream Descriptor Control 0 (SDnCTL0) - 8-bit
pub const REG_SD_CTL0: u32 = 0x00;

/// Stream Descriptor Control 1 (SDnCTL1) - 8-bit
pub const REG_SD_CTL1: u32 = 0x01;

/// Stream Descriptor Control 2 (SDnCTL2) - 8-bit
pub const REG_SD_CTL2: u32 = 0x02;

/// Stream Descriptor Status (SDnSTS) - 8-bit
pub const REG_SD_STS: u32 = 0x03;

/// Stream Descriptor Link Position in Buffer (SDnLPIB) - 32-bit
pub const REG_SD_LPIB: u32 = 0x04;

/// Stream Descriptor Cyclic Buffer Length (SDnCBL) - 32-bit
pub const REG_SD_CBL: u32 = 0x08;

/// Stream Descriptor Last Valid Index (SDnLVI) - 16-bit
pub const REG_SD_LVI: u32 = 0x0C;

/// Stream Descriptor FIFO Size (SDnFIFOS) - 16-bit
pub const REG_SD_FIFOS: u32 = 0x10;

/// Stream Descriptor Format (SDnFMT) - 16-bit
pub const REG_SD_FMT: u32 = 0x12;

/// Stream Descriptor BDL Lower Base Address (SDnBDPL) - 32-bit
pub const REG_SD_BDPL: u32 = 0x18;

/// Stream Descriptor BDL Upper Base Address (SDnBDPU) - 32-bit
pub const REG_SD_BDPU: u32 = 0x1C;

/// Stream Descriptor Size
pub const STREAM_DESC_SIZE: u32 = 0x20;

// ============================================================================
// Stream Descriptor Control Bit Definitions
// ============================================================================

/// Stream Reset (SRST) - Bit 0 of CTL0
pub const SD_CTL0_SRST: u8 = 1 << 0;

/// Stream Run (RUN) - Bit 1 of CTL0
pub const SD_CTL0_RUN: u8 = 1 << 1;

/// Interrupt on Completion Enable (IOCE) - Bit 2 of CTL0
pub const SD_CTL0_IOCE: u8 = 1 << 2;

/// FIFO Error Interrupt Enable (FEIE) - Bit 3 of CTL0
pub const SD_CTL0_FEIE: u8 = 1 << 3;

/// Descriptor Error Interrupt Enable (DEIE) - Bit 4 of CTL0
pub const SD_CTL0_DEIE: u8 = 1 << 4;

/// Stripe Control (STRIPE) - Bits 0-1 of CTL2
pub const SD_CTL2_STRIPE_MASK: u8 = 0x03;

/// Traffic Priority (TP) - Bit 2 of CTL2
pub const SD_CTL2_TP: u8 = 1 << 2;

/// Bidirectional Direction Control (DIR) - Bit 3 of CTL2
pub const SD_CTL2_DIR: u8 = 1 << 3;

/// Stream Number (STRM) - Bits 4-7 of CTL2
pub const SD_CTL2_STRM_SHIFT: u8 = 4;
pub const SD_CTL2_STRM_MASK: u8 = 0xF0;

// ============================================================================
// Stream Descriptor Status Bit Definitions
// ============================================================================

/// Buffer Completion Interrupt Status (BCIS) - Bit 2
pub const SD_STS_BCIS: u8 = 1 << 2;

/// FIFO Error (FIFOE) - Bit 3
pub const SD_STS_FIFOE: u8 = 1 << 3;

/// Descriptor Error (DESE) - Bit 4
pub const SD_STS_DESE: u8 = 1 << 4;

/// FIFO Ready (FIFORDY) - Bit 5
pub const SD_STS_FIFORDY: u8 = 1 << 5;

// ============================================================================
// Stream Format (SDnFMT) Bit Definitions
// ============================================================================

/// Number of Channels (CHAN) - Bits 0-3
pub const FMT_CHAN_MASK: u16 = 0x000F;

/// Bits per Sample (BITS) - Bits 4-6
pub const FMT_BITS_SHIFT: u16 = 4;
pub const FMT_BITS_MASK: u16 = 0x0070;

/// Sample Base Rate Divisor (DIV) - Bits 8-10
pub const FMT_DIV_SHIFT: u16 = 8;
pub const FMT_DIV_MASK: u16 = 0x0700;

/// Sample Base Rate Multiple (MULT) - Bits 11-13
pub const FMT_MULT_SHIFT: u16 = 11;
pub const FMT_MULT_MASK: u16 = 0x3800;

/// Sample Base Rate (BASE) - Bit 14
pub const FMT_BASE: u16 = 1 << 14;

/// Stream Type (TYPE) - Bit 15
pub const FMT_TYPE: u16 = 1 << 15;

// Format values for common configurations
/// 8-bit samples
pub const FMT_BITS_8: u16 = 0x00 << 4;
/// 16-bit samples
pub const FMT_BITS_16: u16 = 0x01 << 4;
/// 20-bit samples
pub const FMT_BITS_20: u16 = 0x02 << 4;
/// 24-bit samples
pub const FMT_BITS_24: u16 = 0x03 << 4;
/// 32-bit samples
pub const FMT_BITS_32: u16 = 0x04 << 4;

/// Mono (1 channel)
pub const FMT_CHAN_MONO: u16 = 0x00;
/// Stereo (2 channels)
pub const FMT_CHAN_STEREO: u16 = 0x01;

/// 48kHz base rate
pub const FMT_BASE_48KHZ: u16 = 0;
/// 44.1kHz base rate
pub const FMT_BASE_44KHZ: u16 = FMT_BASE;

// ============================================================================
// Buffer Descriptor List Entry
// ============================================================================

/// BDL entry size in bytes
pub const BDL_ENTRY_SIZE: usize = 16;

/// Maximum BDL entries
pub const BDL_MAX_ENTRIES: usize = 256;

/// BDL IOC (Interrupt on Completion) flag - Bit 0 of control field
pub const BDL_IOC: u32 = 1 << 0;

// ============================================================================
// Codec Command/Response Verbs
// ============================================================================

/// Get Parameter verb
pub const VERB_GET_PARAM: u32 = 0xF0000;

/// Get Connection Select Control verb
pub const VERB_GET_CONN_SEL: u32 = 0xF0100;

/// Set Connection Select Control verb
pub const VERB_SET_CONN_SEL: u32 = 0x70100;

/// Get Connection List Entry verb
pub const VERB_GET_CONN_LIST: u32 = 0xF0200;

/// Get Processing State verb
pub const VERB_GET_PROC_STATE: u32 = 0xF0300;

/// Set Processing State verb
pub const VERB_SET_PROC_STATE: u32 = 0x70300;

/// Get Coefficient Index verb
pub const VERB_GET_COEF_IDX: u32 = 0xD0000;

/// Set Coefficient Index verb
pub const VERB_SET_COEF_IDX: u32 = 0x50000;

/// Get Processing Coefficient verb
pub const VERB_GET_COEF: u32 = 0xC0000;

/// Set Processing Coefficient verb
pub const VERB_SET_COEF: u32 = 0x40000;

/// Get Amplifier Gain/Mute verb
pub const VERB_GET_AMP_GAIN: u32 = 0xB0000;

/// Set Amplifier Gain/Mute verb
pub const VERB_SET_AMP_GAIN: u32 = 0x30000;

/// Get Converter Format verb
pub const VERB_GET_CONV_FMT: u32 = 0xA0000;

/// Set Converter Format verb
pub const VERB_SET_CONV_FMT: u32 = 0x20000;

/// Get Digital Converter Control verb
pub const VERB_GET_DIG_CVT: u32 = 0xF0D00;

/// Set Digital Converter Control 1 verb
pub const VERB_SET_DIG_CVT_1: u32 = 0x70D00;

/// Set Digital Converter Control 2 verb
pub const VERB_SET_DIG_CVT_2: u32 = 0x70E00;

/// Get Power State verb
pub const VERB_GET_POWER: u32 = 0xF0500;

/// Set Power State verb
pub const VERB_SET_POWER: u32 = 0x70500;

/// Get Converter Stream/Channel verb
pub const VERB_GET_CONV_STREAM: u32 = 0xF0600;

/// Set Converter Stream/Channel verb
pub const VERB_SET_CONV_STREAM: u32 = 0x70600;

/// Get Pin Widget Control verb
pub const VERB_GET_PIN_CTL: u32 = 0xF0700;

/// Set Pin Widget Control verb
pub const VERB_SET_PIN_CTL: u32 = 0x70700;

/// Get Unsolicited Response verb
pub const VERB_GET_UNSOL: u32 = 0xF0800;

/// Set Unsolicited Response verb
pub const VERB_SET_UNSOL: u32 = 0x70800;

/// Get Pin Sense verb
pub const VERB_GET_PIN_SENSE: u32 = 0xF0900;

/// Execute Pin Sense verb
pub const VERB_EXEC_PIN_SENSE: u32 = 0x70900;

/// Get EAPD/BTL Enable verb
pub const VERB_GET_EAPD: u32 = 0xF0C00;

/// Set EAPD/BTL Enable verb
pub const VERB_SET_EAPD: u32 = 0x70C00;

/// Get GPI Data verb
pub const VERB_GET_GPI_DATA: u32 = 0xF1000;

/// Set GPI Data verb
pub const VERB_SET_GPI_DATA: u32 = 0x71000;

/// Get GPI Wake Enable Mask verb
pub const VERB_GET_GPI_WAKE: u32 = 0xF1100;

/// Set GPI Wake Enable Mask verb
pub const VERB_SET_GPI_WAKE: u32 = 0x71100;

/// Get GPI Unsolicited Enable Mask verb
pub const VERB_GET_GPI_UNSOL: u32 = 0xF1200;

/// Set GPI Unsolicited Enable Mask verb
pub const VERB_SET_GPI_UNSOL: u32 = 0x71200;

/// Get GPI Sticky Mask verb
pub const VERB_GET_GPI_STICKY: u32 = 0xF1300;

/// Set GPI Sticky Mask verb
pub const VERB_SET_GPI_STICKY: u32 = 0x71300;

/// Get GPO Data verb
pub const VERB_GET_GPO_DATA: u32 = 0xF1400;

/// Set GPO Data verb
pub const VERB_SET_GPO_DATA: u32 = 0x71400;

/// Get GPIO Data verb
pub const VERB_GET_GPIO_DATA: u32 = 0xF1500;

/// Set GPIO Data verb
pub const VERB_SET_GPIO_DATA: u32 = 0x71500;

/// Get GPIO Enable Mask verb
pub const VERB_GET_GPIO_EN: u32 = 0xF1600;

/// Set GPIO Enable Mask verb
pub const VERB_SET_GPIO_EN: u32 = 0x71600;

/// Get GPIO Direction verb
pub const VERB_GET_GPIO_DIR: u32 = 0xF1700;

/// Set GPIO Direction verb
pub const VERB_SET_GPIO_DIR: u32 = 0x71700;

/// Get GPIO Wake Enable Mask verb
pub const VERB_GET_GPIO_WAKE: u32 = 0xF1800;

/// Set GPIO Wake Enable Mask verb
pub const VERB_SET_GPIO_WAKE: u32 = 0x71800;

/// Get GPIO Unsolicited Enable Mask verb
pub const VERB_GET_GPIO_UNSOL: u32 = 0xF1900;

/// Set GPIO Unsolicited Enable Mask verb
pub const VERB_SET_GPIO_UNSOL: u32 = 0x71900;

/// Get GPIO Sticky Mask verb
pub const VERB_GET_GPIO_STICKY: u32 = 0xF1A00;

/// Set GPIO Sticky Mask verb
pub const VERB_SET_GPIO_STICKY: u32 = 0x71A00;

/// Get Beep Generation verb
pub const VERB_GET_BEEP: u32 = 0xF0A00;

/// Set Beep Generation verb
pub const VERB_SET_BEEP: u32 = 0x70A00;

/// Get Volume Knob verb
pub const VERB_GET_VOL_KNOB: u32 = 0xF0F00;

/// Set Volume Knob verb
pub const VERB_SET_VOL_KNOB: u32 = 0x70F00;

/// Get Subsystem ID verb
pub const VERB_GET_SUBSYS: u32 = 0xF2000;

/// Set Subsystem ID 1 verb
pub const VERB_SET_SUBSYS_1: u32 = 0x72000;

/// Set Subsystem ID 2 verb
pub const VERB_SET_SUBSYS_2: u32 = 0x72100;

/// Get Configuration Default verb
pub const VERB_GET_CONFIG_DEFAULT: u32 = 0xF1C00;

/// Set Configuration Default 1 verb
pub const VERB_SET_CONFIG_DEFAULT_1: u32 = 0x71C00;

/// Set Configuration Default 2 verb
pub const VERB_SET_CONFIG_DEFAULT_2: u32 = 0x71D00;

/// Set Configuration Default 3 verb
pub const VERB_SET_CONFIG_DEFAULT_3: u32 = 0x71E00;

/// Set Configuration Default 4 verb
pub const VERB_SET_CONFIG_DEFAULT_4: u32 = 0x71F00;

/// Function Reset verb
pub const VERB_FUNC_RESET: u32 = 0x7FF00;

// ============================================================================
// Codec Parameters (for GET_PARAM verb)
// ============================================================================

/// Vendor ID Parameter
pub const PARAM_VENDOR_ID: u8 = 0x00;

/// Revision ID Parameter
pub const PARAM_REVISION_ID: u8 = 0x02;

/// Subordinate Node Count Parameter
pub const PARAM_SUB_NODE_COUNT: u8 = 0x04;

/// Function Group Type Parameter
pub const PARAM_FUNC_GROUP_TYPE: u8 = 0x05;

/// Audio Function Group Capabilities Parameter
pub const PARAM_AFG_CAPS: u8 = 0x08;

/// Audio Widget Capabilities Parameter
pub const PARAM_WIDGET_CAPS: u8 = 0x09;

/// Sample Size/Rate Capabilities Parameter
pub const PARAM_PCM_CAPS: u8 = 0x0A;

/// Stream Formats Parameter
pub const PARAM_STREAM_FORMATS: u8 = 0x0B;

/// Pin Capabilities Parameter
pub const PARAM_PIN_CAPS: u8 = 0x0C;

/// Input Amplifier Capabilities Parameter
pub const PARAM_IN_AMP_CAPS: u8 = 0x0D;

/// Output Amplifier Capabilities Parameter
pub const PARAM_OUT_AMP_CAPS: u8 = 0x12;

/// Connection List Length Parameter
pub const PARAM_CONN_LIST_LEN: u8 = 0x0E;

/// Supported Power States Parameter
pub const PARAM_POWER_STATES: u8 = 0x0F;

/// Processing Capabilities Parameter
pub const PARAM_PROC_CAPS: u8 = 0x10;

/// GPIO Count Parameter
pub const PARAM_GPIO_COUNT: u8 = 0x11;

/// Volume Knob Capabilities Parameter
pub const PARAM_VOL_KNOB_CAPS: u8 = 0x13;

// ============================================================================
// Widget Types (from Audio Widget Capabilities Parameter)
// ============================================================================

/// Widget Type: Audio Output
pub const WIDGET_TYPE_AUDIO_OUTPUT: u8 = 0x00;

/// Widget Type: Audio Input
pub const WIDGET_TYPE_AUDIO_INPUT: u8 = 0x01;

/// Widget Type: Audio Mixer
pub const WIDGET_TYPE_AUDIO_MIXER: u8 = 0x02;

/// Widget Type: Audio Selector
pub const WIDGET_TYPE_AUDIO_SELECTOR: u8 = 0x03;

/// Widget Type: Pin Complex
pub const WIDGET_TYPE_PIN_COMPLEX: u8 = 0x04;

/// Widget Type: Power Widget
pub const WIDGET_TYPE_POWER: u8 = 0x05;

/// Widget Type: Volume Knob
pub const WIDGET_TYPE_VOLUME_KNOB: u8 = 0x06;

/// Widget Type: Beep Generator
pub const WIDGET_TYPE_BEEP_GEN: u8 = 0x07;

/// Widget Type: Vendor Defined
pub const WIDGET_TYPE_VENDOR: u8 = 0x0F;

// ============================================================================
// Pin Widget Control Bits
// ============================================================================

/// Headphone Enable (HPHN) - Bit 7
pub const PIN_CTL_HP_EN: u8 = 1 << 7;

/// Output Enable (OUT) - Bit 6
pub const PIN_CTL_OUT_EN: u8 = 1 << 6;

/// Input Enable (IN) - Bit 5
pub const PIN_CTL_IN_EN: u8 = 1 << 5;

/// Voltage Reference Enable (VREF) - Bits 0-2
pub const PIN_CTL_VREF_MASK: u8 = 0x07;

/// VREF: High-Z
pub const PIN_VREF_HIZ: u8 = 0x00;
/// VREF: 50%
pub const PIN_VREF_50: u8 = 0x01;
/// VREF: Ground
pub const PIN_VREF_GRD: u8 = 0x02;
/// VREF: 80%
pub const PIN_VREF_80: u8 = 0x04;
/// VREF: 100%
pub const PIN_VREF_100: u8 = 0x05;

// ============================================================================
// EAPD/BTL Enable Bits
// ============================================================================

/// BTL Enable - Bit 0
pub const EAPD_BTL: u8 = 1 << 0;

/// EAPD Enable - Bit 1
pub const EAPD_EAPD: u8 = 1 << 1;

/// L/R Swap - Bit 2
pub const EAPD_LR_SWAP: u8 = 1 << 2;

// ============================================================================
// Power State Values
// ============================================================================

/// Power State: D0 (Full On)
pub const POWER_D0: u8 = 0x00;

/// Power State: D1
pub const POWER_D1: u8 = 0x01;

/// Power State: D2
pub const POWER_D2: u8 = 0x02;

/// Power State: D3 (Off)
pub const POWER_D3: u8 = 0x03;

// ============================================================================
// Amplifier Gain/Mute Bits
// ============================================================================

/// Gain value mask (bits 0-6)
pub const AMP_GAIN_MASK: u16 = 0x7F;

/// Mute bit (bit 7)
pub const AMP_MUTE: u16 = 1 << 7;

/// Index value (bits 8-11) for get
pub const AMP_INDEX_SHIFT: u16 = 8;
pub const AMP_INDEX_MASK: u16 = 0x0F00;

/// Left channel (bit 13)
pub const AMP_LEFT: u16 = 1 << 13;

/// Right channel (bit 12)
pub const AMP_RIGHT: u16 = 1 << 12;

/// Input amplifier select for GET verb (bit 15)
/// When set, reads the input amplifier; when clear, reads the output amplifier
pub const AMP_INPUT: u16 = 1 << 15;

/// Output amplifier select for GET verb (bit 15 = 0)
/// Note: For GET Amp Gain/Mute, bit 15 selects input(1) or output(0)
/// This constant is provided for clarity but equals 0 (output is default)
pub const AMP_OUTPUT_GET: u16 = 0;

/// Set Output amplifier (bit 15) for SET verb
/// When set in SET Amp Gain/Mute, the output amplifier is modified
pub const AMP_SET_OUTPUT: u16 = 1 << 15;

/// Set Input amplifier (bit 14) for SET verb
/// When set in SET Amp Gain/Mute, the input amplifier is modified
pub const AMP_SET_INPUT: u16 = 1 << 14;

/// Set Left (bit 13) for set
pub const AMP_SET_LEFT: u16 = 1 << 13;

/// Set Right (bit 12) for set
pub const AMP_SET_RIGHT: u16 = 1 << 12;

// ============================================================================
// Beep Generation Control
// ============================================================================

/// Beep Duration/Frequency mask
pub const BEEP_FREQ_MASK: u8 = 0xFF;

/// Beep off
pub const BEEP_OFF: u8 = 0x00;

// Beep frequency calculation: freq = 48000 / (n * 4)
// For example: n=60 gives 200Hz, n=30 gives 400Hz

// ============================================================================
// Stream/Channel Assignment
// ============================================================================

/// Stream number shift
pub const CONV_STREAM_SHIFT: u8 = 4;

/// Stream number mask
pub const CONV_STREAM_MASK: u8 = 0xF0;

/// Channel number mask
pub const CONV_CHANNEL_MASK: u8 = 0x0F;

// ============================================================================
// CORB/RIRB Entry Structures
// ============================================================================

/// CORB Entry: 32-bit command verb
pub const CORB_ENTRY_SIZE: usize = 4;

/// RIRB Entry: 64-bit (32-bit response + 32-bit response ex)
pub const RIRB_ENTRY_SIZE: usize = 8;

// ============================================================================
// Timing Constants
// ============================================================================

/// Controller reset timeout (microseconds)
pub const RESET_TIMEOUT_US: u64 = 1_000_000;

/// Codec detection timeout (microseconds)
pub const CODEC_TIMEOUT_US: u64 = 1_000;

/// Command timeout (microseconds)
pub const CMD_TIMEOUT_US: u64 = 100_000;

/// Stream operation timeout (microseconds)
pub const STREAM_TIMEOUT_US: u64 = 100_000;

// ============================================================================
// Buffer Sizes
// ============================================================================

/// Default CORB size (256 entries)
pub const DEFAULT_CORB_SIZE: usize = 256;

/// Default RIRB size (256 entries)
pub const DEFAULT_RIRB_SIZE: usize = 256;

/// Default audio buffer size (16KB per buffer)
pub const DEFAULT_BUFFER_SIZE: usize = 16384;

/// Number of buffer descriptors
pub const DEFAULT_BDL_COUNT: usize = 4;

// ============================================================================
// Stream Register Base Calculation
// ============================================================================

/// Input stream base offset
pub const INPUT_STREAM_BASE: u32 = 0x80;

/// Output stream base offset
pub const OUTPUT_STREAM_BASE: u32 = 0x80;

/// Calculate stream descriptor offset
/// For input streams: 0x80 + stream_index * 0x20
/// For output streams: depends on number of input streams
#[inline]
pub const fn stream_offset(is_output: bool, num_input_streams: u32, stream_index: u32) -> u32 {
    if is_output {
        INPUT_STREAM_BASE + (num_input_streams + stream_index) * STREAM_DESC_SIZE
    } else {
        INPUT_STREAM_BASE + stream_index * STREAM_DESC_SIZE
    }
}
