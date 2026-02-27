// ============================================================================
// drivers/hda - Intel High Definition Audio (HDA) driver components
// ============================================================================
#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod codec;
pub mod hda;
pub mod mixer;
pub mod regs;
pub mod stream;
pub mod types;

// Re-export commonly used types and helpers
pub use codec::configure_codec_output;
pub use stream::{StreamConfig, StreamError, StreamResult};
pub use types::{
    BdlEntry, CodecInfo, HdaError, HdaResult, NodeType, RirbEntry, WidgetCaps, make_corb_entry,
};

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    // ========================================================================
    // types.rs tests
    // ========================================================================

    pub fn corb_entry_smoke() -> bool {
        let entry = crate::types::make_corb_entry(3, 5, 0x12345);
        entry == ((3u32 & 0x0F) << 28) | ((5u32) << 20) | (0x12345 & 0xFFFFF)
    }

    pub fn rirb_entry_smoke() -> bool {
        let e = crate::types::RirbEntry {
            response: 0x11223344,
            response_ex: 0x0000000F,
        };
        if e.codec_addr() != 0x0F {
            return false;
        }
        if e.is_unsolicited() {
            return false;
        }
        let e2 = crate::types::RirbEntry {
            response: 0,
            response_ex: 0x10,
        };
        e2.is_unsolicited()
    }

    pub fn bdl_entry_smoke() -> bool {
        let be = crate::types::BdlEntry::new(0x12345678_9ABCDEF0, 0x1000, true);
        be.addr_lo == 0x9ABCDEF0u32
            && be.addr_hi == 0x12345678u32
            && be.length == 0x1000
            && be.ioc == 1
    }

    // ========================================================================
    // codec.rs tests
    // ========================================================================

    pub fn detect_codecs_empty_smoke() -> bool {
        let v = crate::codec::detect_codecs();
        v.is_empty()
    }

    pub fn configure_codec_output_smoke() -> bool {
        let codec = crate::types::CodecInfo {
            address: 0,
            vendor_id: 0,
            device_id: 0,
            revision: 0,
            afg_node: None,
            output_nodes: Vec::new(),
            input_nodes: Vec::new(),
            pin_nodes: Vec::new(),
            beep_node: None,
        };
        let caps = crate::types::WidgetCaps {
            widget_type: crate::types::NodeType::Unknown(0),
            conn_list: false,
            out_amp: false,
            in_amp: false,
            format_override: false,
            stereo: false,
        };
        crate::codec::configure_codec_output(&codec, caps).is_ok()
    }

    // ========================================================================
    // mixer.rs tests
    // ========================================================================

    pub fn mixer_creation_smoke() -> bool {
        let mixer = crate::mixer::Mixer::default_mixer();
        mixer.active_channels() == 0
    }

    pub fn mixer_add_channel_smoke() -> bool {
        let mut mixer = crate::mixer::Mixer::default_mixer();
        let id = match mixer.add_channel(crate::mixer::ChannelConfig::default()) {
            Ok(id) => id,
            Err(_) => return false,
        };
        id > 0 && mixer.active_channels() == 1
    }

    pub fn mixer_volume_smoke() -> bool {
        let mut mixer = crate::mixer::Mixer::default_mixer();
        let id = match mixer.add_channel(crate::mixer::ChannelConfig::default()) {
            Ok(id) => id,
            Err(_) => return false,
        };
        if mixer.set_volume(id, 0.5).is_err() {
            return false;
        }
        let config = match mixer.get_channel_config(id) {
            Some(c) => c,
            None => return false,
        };
        (config.volume - 0.5).abs() < 0.001
    }

    pub fn mixer_pan_smoke() -> bool {
        let mut mixer = crate::mixer::Mixer::default_mixer();
        let id = match mixer.add_channel(crate::mixer::ChannelConfig::default()) {
            Ok(id) => id,
            Err(_) => return false,
        };
        if mixer.set_pan(id, -0.5).is_err() {
            return false;
        }
        let config = match mixer.get_channel_config(id) {
            Some(c) => c,
            None => return false,
        };
        (config.pan - (-0.5)).abs() < 0.001
    }

    pub fn mixer_mono_to_stereo_smoke() -> bool {
        let mono = vec![0.5f32, -0.5, 0.25];
        let stereo = crate::mixer::Mixer::mono_to_stereo(&mono);
        if stereo.len() != 6 {
            return false;
        }
        let expected = vec![0.5f32, 0.5, -0.5, -0.5, 0.25, 0.25];
        stereo == expected
    }

    pub fn mixer_limiter_smoke() -> bool {
        let mut mixer = crate::mixer::Mixer::default_mixer();
        let id = match mixer.add_channel(crate::mixer::ChannelConfig::default()) {
            Ok(id) => id,
            Err(_) => return false,
        };
        // Submit loud interleaved stereo samples at the output sample rate.
        // After mixing and limiter, all output values must be in [-1.0, 1.0].
        let loud_samples = vec![1.5f32, -1.5, 1.5, -1.5, 0.5, -0.5, 0.5, -0.5];
        if mixer.submit_samples_f32(id, &loud_samples).is_err() {
            return false;
        }
        let output = mixer.mix();
        for &sample in output {
            if sample < -1.0 || sample > 1.0 {
                return false;
            }
        }
        true
    }
    #[test]
    fn corb_entry_smoke_test() {
        assert!(corb_entry_smoke());
    }

    #[test]
    fn rirb_entry_smoke_test() {
        assert!(rirb_entry_smoke());
    }

    #[test]
    fn bdl_entry_smoke_test() {
        assert!(bdl_entry_smoke());
    }

    #[test]
    fn detect_codecs_empty_smoke_test() {
        assert!(detect_codecs_empty_smoke());
    }

    #[test]
    fn configure_codec_output_smoke_test() {
        assert!(configure_codec_output_smoke());
    }

    #[test]
    fn mixer_creation_smoke_test() {
        assert!(mixer_creation_smoke());
    }

    #[test]
    fn mixer_add_channel_smoke_test() {
        assert!(mixer_add_channel_smoke());
    }

    #[test]
    fn mixer_volume_smoke_test() {
        assert!(mixer_volume_smoke());
    }

    #[test]
    fn mixer_pan_smoke_test() {
        assert!(mixer_pan_smoke());
    }

    #[test]
    fn mixer_mono_to_stereo_smoke_test() {
        assert!(mixer_mono_to_stereo_smoke());
    }

    #[test]
    fn mixer_limiter_smoke_test() {
        assert!(mixer_limiter_smoke());
    }
}
