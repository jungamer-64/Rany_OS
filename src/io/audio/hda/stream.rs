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
use core::ptr::write_volatile;

use super::controller::HdaController;
use super::regs::*;
use super::types::{BdlEntry, HdaError, HdaResult};

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
        crate::io::dma::sfence();

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
        super::codec::configure_codec_output(self, codec_addr, 1)?;

        // Start playback
        self.start_stream(0)?;

        // Wait for playback to complete
        Self::delay_us(duration_ms as u64 * 1000 + 100000);

        // Stop playback
        self.stop_stream(0)?;

        crate::log!("[HDA] Square wave playback complete\n");
        Ok(())
    }
}
