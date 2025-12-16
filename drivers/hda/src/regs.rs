// ============================================================================
// drivers/hda/src/regs.rs - Intel High Definition Audio Register Definitions
// ============================================================================
//!
//! Intel High Definition Audio register definitions (migrated from kernel)
//!
#![allow(dead_code)]

// PCI Configuration Space
pub const HDA_VENDOR_INTEL: u16 = 0x8086;
pub const HDA_DEVICE_QEMU: u16 = 0x2668;

pub const HDA_CLASS: u8 = 0x04;
pub const HDA_SUBCLASS: u8 = 0x03;

// Global Registers
pub const REG_GCAP: u32 = 0x00;
pub const REG_VMIN: u32 = 0x02;
pub const REG_VMAJ: u32 = 0x03;
pub const REG_OUTPAY: u32 = 0x04;
pub const REG_INPAY: u32 = 0x06;
pub const REG_GCTL: u32 = 0x08;
pub const REG_WAKEEN: u32 = 0x0C;
pub const REG_STATESTS: u32 = 0x0E;
pub const REG_GSTS: u32 = 0x10;
pub const REG_OUTSTRMPAY: u32 = 0x18;
pub const REG_INSTRMPAY: u32 = 0x1A;
pub const REG_INTCTL: u32 = 0x20;
pub const REG_INTSTS: u32 = 0x24;
pub const REG_WALCLK: u32 = 0x30;
pub const REG_SSYNC: u32 = 0x38;

// GCTL bits
pub const GCTL_CRST: u32 = 1 << 0;
pub const GCTL_FCNTRL: u32 = 1 << 1;
pub const GCTL_UNSOL: u32 = 1 << 8;

// INTCTL/INTSTS
pub const INTCTL_SIE_MASK: u32 = 0x3FFFFFFF;
pub const INTCTL_CIE: u32 = 1 << 30;
pub const INTCTL_GIE: u32 = 1 << 31;

pub const INTSTS_SIS_MASK: u32 = 0x3FFFFFFF;
pub const INTSTS_CIS: u32 = 1 << 30;
pub const INTSTS_GIS: u32 = 1 << 31;

// CORB
pub const REG_CORBLBASE: u32 = 0x40;
pub const REG_CORBUBASE: u32 = 0x44;
pub const REG_CORBWP: u32 = 0x48;
pub const REG_CORBRP: u32 = 0x4A;
pub const REG_CORBCTL: u32 = 0x4C;
pub const REG_CORBSTS: u32 = 0x4D;
pub const REG_CORBSIZE: u32 = 0x4E;

pub const CORBCTL_CMEIE: u8 = 1 << 0;
pub const CORBCTL_CORBRUN: u8 = 1 << 1;

pub const CORBSTS_CMEI: u8 = 1 << 0;
pub const CORBRP_RST: u16 = 1 << 15;

pub const CORBSIZE_SZCAP_SHIFT: u8 = 4;
pub const CORBSIZE_SZCAP_MASK: u8 = 0xF0;
pub const CORBSIZE_SIZE_MASK: u8 = 0x03;
pub const CORBSIZE_2: u8 = 0x00;
pub const CORBSIZE_16: u8 = 0x01;
pub const CORBSIZE_256: u8 = 0x02;

// RIRB
pub const REG_RIRBLBASE: u32 = 0x50;
pub const REG_RIRBUBASE: u32 = 0x54;
pub const REG_RIRBWP: u32 = 0x58;
pub const REG_RINTCNT: u32 = 0x5A;
pub const REG_RIRBCTL: u32 = 0x5C;
pub const REG_RIRBSTS: u32 = 0x5D;
pub const REG_RIRBSIZE: u32 = 0x5E;

pub const RIRBWP_RST: u16 = 1 << 15;
pub const RIRBCTL_RINTCTL: u8 = 1 << 0;
pub const RIRBCTL_DMAEN: u8 = 1 << 1;
pub const RIRBCTL_OIC: u8 = 1 << 2;

pub const RIRBSTS_RINTFL: u8 = 1 << 0;
pub const RIRBSTS_OIS: u8 = 1 << 2;

pub const RIRBSIZE_SZCAP_SHIFT: u8 = 4;
pub const RIRBSIZE_SZCAP_MASK: u8 = 0xF0;
pub const RIRBSIZE_SIZE_MASK: u8 = 0x03;
pub const RIRBSIZE_2: u8 = 0x00;
pub const RIRBSIZE_16: u8 = 0x01;
pub const RIRBSIZE_256: u8 = 0x02;

// Immediate Command
pub const REG_ICO: u32 = 0x60;
pub const REG_IRI: u32 = 0x64;
pub const REG_ICS: u32 = 0x68;

pub const ICS_ICB: u16 = 1 << 0;
pub const ICS_IRV: u16 = 1 << 1;

// DMA position
pub const REG_DPLBASE: u32 = 0x70;
pub const REG_DPUBASE: u32 = 0x74;
pub const DPLBASE_DPBE: u32 = 1 << 0;

// Stream descriptor
pub const REG_SD_CTL0: u32 = 0x00;
pub const REG_SD_CTL1: u32 = 0x01;
pub const REG_SD_CTL2: u32 = 0x02;
pub const REG_SD_STS: u32 = 0x03;
pub const REG_SD_LPIB: u32 = 0x04;
pub const REG_SD_CBL: u32 = 0x08;
pub const REG_SD_LVI: u32 = 0x0C;
pub const REG_SD_FIFOS: u32 = 0x10;
pub const REG_SD_FMT: u32 = 0x12;
pub const REG_SD_BDPL: u32 = 0x18;
pub const REG_SD_BDPU: u32 = 0x1C;
pub const STREAM_DESC_SIZE: u32 = 0x20;

pub const SD_CTL0_SRST: u8 = 1 << 0;
pub const SD_CTL0_RUN: u8 = 1 << 1;
pub const SD_CTL0_IOCE: u8 = 1 << 2;
pub const SD_CTL0_FEIE: u8 = 1 << 3;
pub const SD_CTL0_DEIE: u8 = 1 << 4;

pub const SD_CTL2_STRIPE_MASK: u8 = 0x03;
pub const SD_CTL2_TP: u8 = 1 << 2;
pub const SD_CTL2_DIR: u8 = 1 << 3;
pub const SD_CTL2_STRM_SHIFT: u8 = 4;
pub const SD_CTL2_STRM_MASK: u8 = 0xF0;

// CORB/RIRB entry sizes and timeouts
pub const CORB_ENTRY_SIZE: usize = 4;
pub const RIRB_ENTRY_SIZE: usize = 8;

// Stream/Channel Assignment
pub const CONV_STREAM_SHIFT: u8 = 4;
pub const CONV_STREAM_MASK: u8 = 0xF0;
pub const CONV_CHANNEL_MASK: u8 = 0x0F;

// Stream Descriptor Sizes
pub const BDL_ENTRY_SIZE: usize = 16;

// Stream/Data Formats
pub const FMT_CHAN_MASK: u16 = 0x000F;
pub const FMT_MULT_SHIFT: u16 = 11;
pub const FMT_BASE: u16 = 1 << 14;
pub const FMT_BITS_8: u16 = 0x00 << 4;
pub const FMT_BITS_16: u16 = 0x01 << 4;
pub const FMT_BITS_20: u16 = 0x02 << 4;
pub const FMT_BITS_24: u16 = 0x03 << 4;
pub const FMT_BITS_32: u16 = 0x04 << 4;
pub const FMT_BASE_48KHZ: u16 = 0;
pub const FMT_BASE_44KHZ: u16 = FMT_BASE;

// Buffer Sizes
pub const BDL_ENTRY_SIZE_16: usize = 16; // alias for clarity

// Timeouts (microseconds)
pub const RESET_TIMEOUT_US: u64 = 1_000_000;
pub const CODEC_TIMEOUT_US: u64 = 1_000;
pub const CMD_TIMEOUT_US: u64 = 100_000;

// Controller Stream Base and helper
pub const INPUT_STREAM_BASE: u32 = 0x80;
pub const OUTPUT_STREAM_BASE: u32 = 0x80;

#[inline]
pub const fn stream_offset(is_output: bool, num_input_streams: u32, stream_index: u32) -> u32 {
    if is_output {
        INPUT_STREAM_BASE + (num_input_streams + stream_index) * STREAM_DESC_SIZE
    } else {
        INPUT_STREAM_BASE + stream_index * STREAM_DESC_SIZE
    }
}

// Codec verbs
pub const VERB_GET_PARAM: u32 = 0xF0000;
pub const VERB_SET_AMP_GAIN: u32 = 0x30000;
pub const VERB_SET_CONV_FMT: u32 = 0x20000;
pub const VERB_SET_POWER: u32 = 0x70500;
pub const VERB_SET_CONV_STREAM: u32 = 0x70600;
pub const VERB_SET_PIN_CTL: u32 = 0x70700;
pub const VERB_SET_EAPD: u32 = 0x70C00;
pub const VERB_SET_BEEP: u32 = 0x70A00;

// Pin/Power/Beep constants
pub const PIN_CTL_OUT_EN: u8 = 1 << 6;
pub const EAPD_EAPD: u8 = 1 << 1;
pub const POWER_D0: u8 = 0x00;

pub const AMP_SET_OUTPUT: u16 = 1 << 15;

// Beep Generation Control
pub const BEEP_FREQ_MASK: u8 = 0xFF;
pub const BEEP_OFF: u8 = 0x00;
