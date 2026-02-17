// ============================================================================
// src/io/audio/hda/stream.rs - Audio Stream Management
// ============================================================================
//!
//! HDA オーディオストリームの管理。
//!
//! - ストリーム設定
//! - BDL設定
//! - オーディオ再生
//! - ビープ音生成

#![allow(dead_code)]

use alloc::vec::Vec;
// centralize volatile writes via mmio helper

use super::controller::HdaController;
use super::regs::*;
use super::types::{BdlEntry, HdaError, HdaResult, CodecInfo, WidgetCaps, NodeType};

// ============================================================================
// Audio Output Stream Management
// ============================================================================

impl HdaController {
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

        log::info!(
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
        log::info!("[HDA] Stream format: 0x{:04x}\n", format);

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
            _ => {}                                   // Default to 48kHz
        }

        format
    }

    /// Setup Buffer Descriptor List for a stream
    ///
    /// `buffer_device_addr` is the hardware-visible address of the audio buffer.
    pub fn setup_bdl(
        &mut self,
        stream_index: u32,
        buffer_device_addr: u64,
        buffer_size: u32,
        num_entries: u32,
    ) -> HdaResult<()> {
        if stream_index >= self.num_output_streams {
            return Err(HdaError::StreamError("Invalid stream index".into()));
        }

        let stream_base = stream_offset(true, self.num_input_streams, stream_index);

        // Allocate BDL
        let bdl_size = (num_entries as usize) * BDL_ENTRY_SIZE;
        let (bdl_virt, bdl_dev) = Self::alloc_dma_buffer(bdl_size)?;
        self.stream_bdl_addrs[stream_index as usize] = bdl_virt;
        self.stream_bdl_device_addrs[stream_index as usize] = bdl_dev;

        // Fill BDL entries (using virtual address for CPU writes,
        // but device address for audio buffer references in each entry)
        let segment_size = buffer_size / num_entries;
        for i in 0..num_entries {
            let entry_addr = bdl_virt + (i as u64 * BDL_ENTRY_SIZE as u64);
            let buf_offset = buffer_device_addr + (i as u64 * segment_size as u64);

            let entry = BdlEntry::new(buf_offset, segment_size, i == num_entries - 1);

            // SAFETY: entry_addr points to a valid DMA buffer allocated by alloc_dma_buffer.
            // BdlEntry is repr(C, align(16)) ensuring proper alignment.
            // The write is within bounds (i < num_entries).
            unsafe {
                crate::io::mmio::volatile_write::<BdlEntry>(entry_addr as usize, entry);
            }
        }

        // SAFETY: SFENCE ensures all BDL entries are visible to the HDA controller
        // before we configure the stream to use this BDL.
        crate::io::dma::sfence();

        // Set BDL address (hardware-visible device address)
        self.write32(stream_base + REG_SD_BDPL, bdl_dev as u32);
        self.write32(stream_base + REG_SD_BDPU, (bdl_dev >> 32) as u32);

        // Set cyclic buffer length
        self.write32(stream_base + REG_SD_CBL, buffer_size);

        // Set last valid index
        self.write16(stream_base + REG_SD_LVI, (num_entries - 1) as u16);

        log::info!(
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

        log::info!("[HDA] Stream {} started\n", stream_index);
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

        log::info!("[HDA] Stream {} stopped\n", stream_index);
        Ok(())
    }
}

// ============================================================================
// Beep Generation
// ============================================================================

impl HdaController {
    /// Play a beep tone using the codec's beep generator
    pub fn beep(&self, codec_addr: u8, frequency_divisor: u8) -> HdaResult<()> {
        let codec = self
            .codecs
            .iter()
            .find(|c| c.address == codec_addr)
            .ok_or(HdaError::NoCodec)?;

        let beep_node = codec
            .beep_node
            .ok_or_else(|| HdaError::InitFailed("No beep generator found".into()))?;

        log::info!(
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
    pub fn beep_duration(
        &self,
        codec_addr: u8,
        frequency_hz: u32,
        duration_ms: u32,
    ) -> HdaResult<()> {
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
}

// ============================================================================
// Square Wave Generation (Software-based)
// ============================================================================

impl HdaController {
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

    /// Generate a stereo square wave into a buffer slice
    fn generate_stereo_square_wave(buffer_slice: &mut [i16], samples: usize, frequency: u32, sample_rate: u32) {
        let mono_buffer: Vec<i16> = (0..samples)
            .map(|i| {
                let samples_per_period = sample_rate / frequency;
                let half_period = samples_per_period / 2;
                let pos = i as u32 % samples_per_period;
                if pos < half_period {
                    16000i16
                } else {
                    -16000i16
                }
            })
            .collect();
        for (i, &sample) in mono_buffer.iter().enumerate() {
            buffer_slice[i * 2] = sample;
            buffer_slice[i * 2 + 1] = sample;
        }
    }

    /// Configure codec and run stream playback
    fn configure_and_play_stream(
        &mut self,
        codec_addr: u8,
        audio_dev: u64,
        buffer_size: u32,
        duration_ms: u32,
        sample_rate: u32,
        bits: u8,
        channels: u8,
    ) -> HdaResult<()> {
        self.setup_output_stream(0, sample_rate, bits, channels)?;
        self.setup_bdl(0, audio_dev, buffer_size, 4)?;
        let codec = self
            .codecs
            .iter()
            .find(|c| c.address == codec_addr)
            .ok_or(HdaError::NoCodec)?;
        let caps = WidgetCaps {
            widget_type: NodeType::AudioOutput,
            conn_list: false,
            out_amp: false,
            in_amp: false,
            format_override: false,
            stereo: false,
        };
        super::codec::configure_codec_output(codec, caps)?;
        self.start_stream(0)?;
        Self::delay_us(duration_ms as u64 * 1000 + 100000);
        self.stop_stream(0)?;
        log::info!("[HDA] Square wave playback complete\n");
        Ok(())
    }

    /// Play a square wave beep using stream output
    pub fn play_square_wave(&mut self, frequency: u32, duration_ms: u32) -> HdaResult<()> {
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
        let (audio_virt, audio_dev) = Self::alloc_dma_buffer(buffer_size)?;
        self.audio_buffers[0] = audio_virt;
        self.audio_buffer_device_addrs[0] = audio_dev;

        // Generate square wave
        // SAFETY: audio_virt points to a valid DMA buffer allocated by alloc_dma_buffer.
        // The buffer size is samples * 2 * sizeof(i16) = buffer_size bytes.
        // We create a mutable slice of samples * 2 i16 values (stereo: L, R pairs).
        let buffer_slice =
            unsafe { core::slice::from_raw_parts_mut(audio_virt as *mut i16, samples * 2) };

        Self::generate_stereo_square_wave(buffer_slice, samples, frequency, SAMPLE_RATE);

        // Configure and play
        self.configure_and_play_stream(codec_addr, audio_dev, buffer_size as u32, duration_ms, SAMPLE_RATE, BITS, CHANNELS)
    }
}
