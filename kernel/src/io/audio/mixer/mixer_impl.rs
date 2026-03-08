use super::*;

impl Mixer {
    /// 新しいミキサーを作成
    pub fn new(config: MixerConfig) -> Self {
        let buffer_size = config.buffer_size * OUTPUT_CHANNELS as usize;
        Self {
            config,
            channels: BTreeMap::new(),
            next_channel_id: AtomicU64::new(1),
            output_buffer: vec![0.0; buffer_size],
            limiter: LimiterState::default(),
        }
    }

    /// デフォルト設定でミキサーを作成
    pub fn default_mixer() -> Self {
        Self::new(MixerConfig::default())
    }

    // ========================================================================
    // Channel Management
    // ========================================================================

    /// チャンネルを追加
    pub fn add_channel(&mut self, config: ChannelConfig) -> MixerResult<u64> {
        if self.channels.len() >= MAX_CHANNELS {
            return Err(MixerError::TooManyChannels);
        }

        // Validate config
        if config.sample_rate == 0 || config.sample_rate > 192000 {
            return Err(MixerError::InvalidSampleRate(config.sample_rate));
        }

        if config.channels == 0 || config.channels > 2 {
            return Err(MixerError::InvalidParameter(
                "channels must be 1 or 2".into(),
            ));
        }

        let id = self.next_channel_id.fetch_add(1, Ordering::SeqCst);
        let channel = MixerChannel::new(id, config);
        self.channels.insert(id, channel);

        Ok(id)
    }

    /// チャンネルを削除
    pub fn remove_channel(&mut self, channel_id: u64) -> MixerResult<()> {
        self.channels
            .remove(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;
        Ok(())
    }

    /// チャンネルの音量を設定
    pub fn set_volume(&mut self, channel_id: u64, volume: f32) -> MixerResult<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;
        channel.config.volume = volume.clamp(0.0, 1.0);
        Ok(())
    }

    /// チャンネルのパンを設定
    pub fn set_pan(&mut self, channel_id: u64, pan: f32) -> MixerResult<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;
        channel.config.pan = pan.clamp(-1.0, 1.0);
        Ok(())
    }

    /// チャンネルをミュート/ミュート解除
    pub fn set_mute(&mut self, channel_id: u64, muted: bool) -> MixerResult<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;
        channel.config.muted = muted;
        Ok(())
    }

    /// マスター音量を設定
    pub fn set_master_volume(&mut self, volume: f32) {
        self.config.master_volume = volume.clamp(0.0, 1.0);
    }

    /// リミッターの有効/無効を設定
    pub fn set_limiter_enabled(&mut self, enabled: bool) {
        self.config.limiter_enabled = enabled;
    }

    // ========================================================================
    // Sample Submission
    // ========================================================================

    /// サンプルをチャンネルに送信（生バイト形式）
    pub fn submit_samples_raw(&mut self, channel_id: u64, data: &[u8]) -> MixerResult<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;

        // Convert raw bytes to f32 based on bit depth
        let samples = Self::convert_to_f32(data, channel.config.bit_depth);

        // Convert to stereo if mono
        let stereo_samples = if channel.config.channels == 1 {
            Self::mono_to_stereo(&samples)
        } else {
            samples
        };

        channel.buffer.extend(stereo_samples);
        Ok(())
    }

    /// サンプルをチャンネルに送信（i16形式）
    pub fn submit_samples_i16(&mut self, channel_id: u64, samples: &[i16]) -> MixerResult<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;

        // Convert i16 to f32
        let f32_samples: Vec<f32> = samples.iter().map(|&s| s as f32 / 32767.0).collect();

        // Convert to stereo if mono
        let stereo_samples = if channel.config.channels == 1 {
            Self::mono_to_stereo(&f32_samples)
        } else {
            f32_samples
        };

        channel.buffer.extend(stereo_samples);
        Ok(())
    }

    /// サンプルをチャンネルに送信（f32形式）
    pub fn submit_samples_f32(&mut self, channel_id: u64, samples: &[f32]) -> MixerResult<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(MixerError::ChannelNotFound(channel_id))?;

        // Convert to stereo if mono
        let stereo_samples = if channel.config.channels == 1 {
            Self::mono_to_stereo(samples)
        } else {
            samples.to_vec()
        };

        channel.buffer.extend(stereo_samples);
        Ok(())
    }

    // ========================================================================
    // Format Conversion
    // ========================================================================

    /// 生バイトをf32に変換
    pub(super) fn convert_to_f32(data: &[u8], bit_depth: BitDepth) -> Vec<f32> {
        match bit_depth {
            BitDepth::U8 => data.iter().map(|&b| (b as f32 - 128.0) / 127.0).collect(),
            BitDepth::S16 => data
                .chunks_exact(2)
                .map(|chunk| {
                    let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
                    sample as f32 / 32767.0
                })
                .collect(),
            BitDepth::S24 => {
                data.chunks_exact(3)
                    .map(|chunk| {
                        let sample = ((chunk[2] as i32) << 16)
                            | ((chunk[1] as i32) << 8)
                            | (chunk[0] as i32);
                        // Sign extend
                        let sample = if sample & 0x800000 != 0 {
                            sample | 0xFF000000u32 as i32
                        } else {
                            sample
                        };
                        sample as f32 / 8388607.0
                    })
                    .collect()
            }
            BitDepth::S32 => data
                .chunks_exact(4)
                .map(|chunk| {
                    let sample = i32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    sample as f32 / 2147483647.0
                })
                .collect(),
            BitDepth::F32 => data
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect(),
        }
    }

    /// モノラルをステレオに変換
    pub(super) fn mono_to_stereo(mono: &[f32]) -> Vec<f32> {
        let mut stereo = Vec::with_capacity(mono.len() * 2);
        for &sample in mono {
            stereo.push(sample); // Left
            stereo.push(sample); // Right
        }
        stereo
    }

    // ========================================================================
    // Resampling (Linear Interpolation)
    // ========================================================================

    /// リサンプリング不要時のファストパス
    pub(super) fn no_resample_fast_path(
        channel: &mut MixerChannel,
        output_frames: usize,
    ) -> Vec<f32> {
        let needed = output_frames * 2; // stereo
        if channel.buffer.len() >= needed {
            channel.buffer.drain(..needed).collect()
        } else {
            let mut result = channel.buffer.drain(..).collect::<Vec<_>>();
            result.resize(needed, 0.0);
            result
        }
    }

    /// 線形補間によるリサンプリング
    pub(super) fn resample_channel(channel: &mut MixerChannel, output_frames: usize) -> Vec<f32> {
        let ratio = channel.resample_ratio();

        // No resampling needed if same sample rate
        if (ratio - 1.0).abs() < 0.0001 {
            return Self::no_resample_fast_path(channel, output_frames);
        }

        let mut output = Vec::with_capacity(output_frames * 2);
        let mut phase = channel.resample_phase;
        let mut prev_l = channel.prev_samples[0];
        let mut prev_r = channel.prev_samples[1];
        let mut buffer_pos = 0;

        for _ in 0..output_frames {
            // Calculate interpolation factor
            // Note: no_std環境ではfract()やlibmが使えないため手動で計算
            let int_part = phase as usize;
            let frac = (phase - int_part as f64) as f32;
            let int_pos = int_part * 2;

            // Get current samples (or use previous if not available)
            let (curr_l, curr_r) = if int_pos + 1 < channel.buffer.len() {
                (channel.buffer[int_pos], channel.buffer[int_pos + 1])
            } else {
                (0.0, 0.0)
            };

            // Linear interpolation
            let out_l = prev_l + (curr_l - prev_l) * frac;
            let out_r = prev_r + (curr_r - prev_r) * frac;

            output.push(out_l);
            output.push(out_r);

            // Advance phase
            phase += ratio;

            // Update previous samples when crossing integer boundary
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while phase >= 1.0 {
                phase -= 1.0;
                buffer_pos += 2;
                if buffer_pos + 1 < channel.buffer.len() {
                    prev_l = channel.buffer[buffer_pos];
                    prev_r = channel.buffer[buffer_pos + 1];
                }
            }
        }

        // Update channel state
        channel.resample_phase = phase;
        channel.prev_samples = [prev_l, prev_r];

        // Remove consumed samples
        if buffer_pos > 0 && buffer_pos <= channel.buffer.len() {
            channel.buffer.drain(..buffer_pos);
        }

        output
    }

    // ========================================================================
    // Volume and Pan
    // ========================================================================

    /// 音量とパンを適用
    #[cfg(not(target_feature = "sse2"))]
    pub(super) fn apply_volume_pan(samples: &mut [f32], volume: f32, pan: f32) {
        // Calculate left/right gain from pan
        // Pan: -1.0 = full left, 0.0 = center, 1.0 = full right
        // Using constant power panning
        let pan_normalized = (pan + 1.0) * 0.5; // 0.0 to 1.0
        let angle = pan_normalized * core::f32::consts::FRAC_PI_2;

        // Use Taylor series approximation for sin/cos in no_std
        let left_gain = volume * cos_approx(angle);
        let right_gain = volume * sin_approx(angle);

        for chunk in samples.chunks_exact_mut(2) {
            chunk[0] *= left_gain;
            chunk[1] *= right_gain;
        }
    }

    /// 音量とパンを適用 (SIMD版)
    #[cfg(target_feature = "sse2")]
    pub(super) fn apply_volume_pan(samples: &mut [f32], volume: f32, pan: f32) {
        use core::arch::x86_64::*;

        let pan_normalized = (pan + 1.0) * 0.5;
        let angle = pan_normalized * core::f32::consts::FRAC_PI_2;
        let left_gain = volume * cos_approx(angle);
        let right_gain = volume * sin_approx(angle);

        // SAFETY: We're using SSE2 which is available on all x86_64 CPUs.
        // The samples slice is properly aligned for f32 operations.
        unsafe {
            let left_vec = _mm_set1_ps(left_gain);
            let right_vec = _mm_set1_ps(right_gain);
            let gain_vec = _mm_unpacklo_ps(left_vec, right_vec); // [L, R, L, R]

            let chunks = samples.len() / 4;
            for i in 0..chunks {
                let ptr = samples.as_mut_ptr().add(i * 4);
                let data = _mm_loadu_ps(ptr);
                let result = _mm_mul_ps(data, gain_vec);
                _mm_storeu_ps(ptr, result);
            }

            // Handle remaining samples
            let remaining_start = chunks * 4;
            for i in (remaining_start..samples.len()).step_by(2) {
                if i + 1 < samples.len() {
                    samples[i] *= left_gain;
                    samples[i + 1] *= right_gain;
                }
            }
        }
    }

    // ========================================================================
    // Soft Limiter
    // ========================================================================

    /// ソフトリミッターを適用
    pub(super) fn apply_limiter_to_buffer(
        limiter: &mut LimiterState,
        limiter_enabled: bool,
        samples: &mut [f32],
    ) {
        if !limiter_enabled {
            return;
        }

        for sample in samples.iter_mut() {
            let abs_sample = sample.abs();

            // Update peak with attack (instant) and release
            if abs_sample > limiter.peak {
                limiter.peak = abs_sample;
                limiter.release_counter = LIMITER_RELEASE_SAMPLES;
            } else if limiter.release_counter > 0 {
                limiter.release_counter -= 1;
            } else {
                // Gradual release
                limiter.peak *= 0.9999;
            }

            // Calculate gain reduction if peak exceeds threshold
            if limiter.peak > LIMITER_THRESHOLD {
                // Soft knee compression
                let over_threshold = limiter.peak - LIMITER_THRESHOLD;
                let knee_start = LIMITER_THRESHOLD - LIMITER_KNEE_WIDTH / 2.0;

                if limiter.peak > knee_start {
                    // In the knee region, apply gradual compression
                    let knee_factor = if over_threshold < LIMITER_KNEE_WIDTH {
                        // Quadratic knee curve
                        let x = over_threshold / LIMITER_KNEE_WIDTH;
                        1.0 - x * x * 0.5
                    } else {
                        // Full limiting above knee
                        LIMITER_THRESHOLD / limiter.peak
                    };

                    // Smoothly transition to target gain
                    let target_gain = knee_factor;
                    limiter.current_gain += (target_gain - limiter.current_gain) * 0.1;
                }
            } else {
                // Release gain back to 1.0
                limiter.current_gain += (1.0 - limiter.current_gain) * 0.001;
            }

            // Apply gain
            *sample *= limiter.current_gain;

            // Hard clip as safety net
            *sample = sample.clamp(-1.0, 1.0);
        }
    }

    /// リミッターを適用（SIMD版、バッチ処理）
    #[cfg(target_feature = "avx")]
    pub(super) fn apply_limiter_simd_static(
        _limiter: &mut LimiterState,
        limiter_enabled: bool,
        samples: &mut [f32],
    ) {
        use core::arch::x86_64::*;

        if !limiter_enabled {
            return;
        }

        // SAFETY: AVX is available and samples are aligned for f32.
        unsafe {
            let threshold = _mm256_set1_ps(LIMITER_THRESHOLD);
            let one = _mm256_set1_ps(1.0);
            let neg_one = _mm256_set1_ps(-1.0);

            let chunks = samples.len() / 8;
            for i in 0..chunks {
                let ptr = samples.as_mut_ptr().add(i * 8);
                let data = _mm256_loadu_ps(ptr);

                // Soft clip using tanh approximation: x / (1 + |x|)
                let abs_data = _mm256_andnot_ps(neg_one, data);
                let denom = _mm256_add_ps(one, abs_data);
                let result = _mm256_div_ps(data, denom);

                // Scale back to threshold range
                let scaled = _mm256_mul_ps(result, threshold);

                _mm256_storeu_ps(ptr, scaled);
            }

            // Handle remaining samples with scalar code
            let remaining_start = chunks * 8;
            for i in remaining_start..samples.len() {
                let x = samples[i];
                samples[i] = (x / (1.0 + x.abs())) * LIMITER_THRESHOLD;
            }
        }
    }

    // ========================================================================
    // Mixing
    // ========================================================================

    /// すべてのチャンネルをミックスして出力を生成
    #[cfg(not(any(target_feature = "sse2", target_feature = "avx")))]
    pub fn mix(&mut self) -> &[f32] {
        let output_frames = self.config.buffer_size;

        // Clear output buffer
        for sample in self.output_buffer.iter_mut() {
            *sample = 0.0;
        }

        // Mix each channel
        for channel in self.channels.values_mut() {
            if channel.config.muted || channel.buffer.is_empty() {
                continue;
            }

            // Resample to output rate
            let mut resampled = Self::resample_channel(channel, output_frames);

            // Apply volume and pan
            Self::apply_volume_pan(&mut resampled, channel.config.volume, channel.config.pan);

            // Add to output buffer
            for (i, &sample) in resampled.iter().enumerate() {
                if i < self.output_buffer.len() {
                    self.output_buffer[i] += sample;
                }
            }
        }

        // Apply master volume
        for sample in self.output_buffer.iter_mut() {
            *sample *= self.config.master_volume;
        }

        // Apply limiter
        Self::apply_limiter_to_buffer(
            &mut self.limiter,
            self.config.limiter_enabled,
            &mut self.output_buffer,
        );

        &self.output_buffer
    }

    #[cfg(all(target_feature = "sse2", not(target_feature = "avx")))]
    pub(super) fn apply_master_volume_sse(buffer: &mut [f32], master_volume: f32) {
        use core::arch::x86_64::*;
        unsafe {
            let master_vol = _mm_set1_ps(master_volume);
            let chunks = buffer.len() / 4;
            for i in 0..chunks {
                let ptr = buffer.as_mut_ptr().add(i * 4);
                let data = _mm_loadu_ps(ptr);
                let result = _mm_mul_ps(data, master_vol);
                _mm_storeu_ps(ptr, result);
            }
            for i in (chunks * 4)..buffer.len() {
                buffer[i] *= master_volume;
            }
        }
    }

    #[cfg(target_feature = "avx")]
    pub(super) fn apply_master_volume_avx(buffer: &mut [f32], master_volume: f32) {
        use core::arch::x86_64::*;
        unsafe {
            let master_vol = _mm256_set1_ps(master_volume);
            let chunks = buffer.len() / 8;
            for i in 0..chunks {
                let ptr = buffer.as_mut_ptr().add(i * 8);
                let data = _mm256_loadu_ps(ptr);
                let result = _mm256_mul_ps(data, master_vol);
                _mm256_storeu_ps(ptr, result);
            }
            for i in (chunks * 8)..buffer.len() {
                buffer[i] *= master_volume;
            }
        }
    }

    /// すべてのチャンネルをミックス (SSE2版)
    #[cfg(all(target_feature = "sse2", not(target_feature = "avx")))]
    pub fn mix(&mut self) -> &[f32] {
        use core::arch::x86_64::*;

        let output_frames = self.config.buffer_size;

        // Clear output buffer using SIMD
        // SAFETY: SSE2 is available, buffer is aligned for f32.
        unsafe {
            let zero = _mm_setzero_ps();
            let chunks = self.output_buffer.len() / 4;
            for i in 0..chunks {
                let ptr = self.output_buffer.as_mut_ptr().add(i * 4);
                _mm_storeu_ps(ptr, zero);
            }
            for i in (chunks * 4)..self.output_buffer.len() {
                self.output_buffer[i] = 0.0;
            }
        }

        // Mix each channel
        for channel in self.channels.values_mut() {
            if channel.config.muted || channel.buffer.is_empty() {
                continue;
            }

            let mut resampled = Self::resample_channel(channel, output_frames);
            Self::apply_volume_pan(&mut resampled, channel.config.volume, channel.config.pan);

            // Add to output buffer using SIMD
            // SAFETY: SSE2 is available, both buffers are properly sized.
            unsafe {
                let chunks = core::cmp::min(resampled.len(), self.output_buffer.len()) / 4;
                for i in 0..chunks {
                    let out_ptr = self.output_buffer.as_mut_ptr().add(i * 4);
                    let in_ptr = resampled.as_ptr().add(i * 4);
                    let out_data = _mm_loadu_ps(out_ptr);
                    let in_data = _mm_loadu_ps(in_ptr);
                    let sum = _mm_add_ps(out_data, in_data);
                    _mm_storeu_ps(out_ptr, sum);
                }

                let remaining_start = chunks * 4;
                for i in remaining_start..core::cmp::min(resampled.len(), self.output_buffer.len())
                {
                    self.output_buffer[i] += resampled[i];
                }
            }
        }

        Self::apply_master_volume_sse(&mut self.output_buffer, self.config.master_volume);

        Self::apply_limiter_to_buffer(
            &mut self.limiter,
            self.config.limiter_enabled,
            &mut self.output_buffer,
        );

        &self.output_buffer
    }

    /// すべてのチャンネルをミックス (AVX版)
    #[cfg(target_feature = "avx")]
    pub fn mix(&mut self) -> &[f32] {
        use core::arch::x86_64::*;

        let output_frames = self.config.buffer_size;

        // Clear output buffer using AVX
        // SAFETY: AVX is available, buffer is aligned for f32.
        unsafe {
            let zero = _mm256_setzero_ps();
            let chunks = self.output_buffer.len() / 8;
            for i in 0..chunks {
                let ptr = self.output_buffer.as_mut_ptr().add(i * 8);
                _mm256_storeu_ps(ptr, zero);
            }
            for i in (chunks * 8)..self.output_buffer.len() {
                self.output_buffer[i] = 0.0;
            }
        }

        // Mix each channel
        for channel in self.channels.values_mut() {
            if channel.config.muted || channel.buffer.is_empty() {
                continue;
            }

            let mut resampled = Self::resample_channel(channel, output_frames);
            Self::apply_volume_pan(&mut resampled, channel.config.volume, channel.config.pan);

            // Add to output buffer using AVX
            // SAFETY: AVX is available, both buffers are properly sized.
            unsafe {
                let chunks = core::cmp::min(resampled.len(), self.output_buffer.len()) / 8;
                for i in 0..chunks {
                    let out_ptr = self.output_buffer.as_mut_ptr().add(i * 8);
                    let in_ptr = resampled.as_ptr().add(i * 8);
                    let out_data = _mm256_loadu_ps(out_ptr);
                    let in_data = _mm256_loadu_ps(in_ptr);
                    let sum = _mm256_add_ps(out_data, in_data);
                    _mm256_storeu_ps(out_ptr, sum);
                }

                let remaining_start = chunks * 8;
                for i in remaining_start..core::cmp::min(resampled.len(), self.output_buffer.len())
                {
                    self.output_buffer[i] += resampled[i];
                }
            }
        }

        Self::apply_master_volume_avx(&mut self.output_buffer, self.config.master_volume);

        Self::apply_limiter_simd_static(
            &mut self.limiter,
            self.config.limiter_enabled,
            &mut self.output_buffer,
        );

        &self.output_buffer
    }

    // ========================================================================
    // Output Conversion
    // ========================================================================

    /// ミックス出力をi16形式で取得
    pub fn mix_to_i16(&mut self) -> Vec<i16> {
        let f32_output = self.mix();
        f32_output.iter().map(|&s| (s * 32767.0) as i16).collect()
    }

    /// ミックス出力を生バイト（i16 LE）で取得
    pub fn mix_to_bytes(&mut self) -> Vec<u8> {
        let i16_output = self.mix_to_i16();
        let mut bytes = Vec::with_capacity(i16_output.len() * 2);
        for sample in i16_output {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        bytes
    }

    // ========================================================================
    // Status & Info
    // ========================================================================

    /// アクティブなチャンネル数を取得
    pub fn active_channels(&self) -> usize {
        self.channels.len()
    }

    /// チャンネルIDのリストを取得
    pub fn channel_ids(&self) -> Vec<u64> {
        self.channels.keys().copied().collect()
    }

    /// チャンネルの設定を取得
    pub fn get_channel_config(&self, channel_id: u64) -> Option<&ChannelConfig> {
        self.channels.get(&channel_id).map(|c| &c.config)
    }

    /// バッファされているサンプル数を取得
    pub fn buffered_samples(&self, channel_id: u64) -> Option<usize> {
        self.channels.get(&channel_id).map(|c| c.buffer.len() / 2) // frames
    }

    /// すべてのチャンネルのバッファをクリア
    pub fn clear_all_buffers(&mut self) {
        for channel in self.channels.values_mut() {
            channel.buffer.clear();
            channel.resample_phase = 0.0;
            channel.prev_samples = [0.0, 0.0];
        }
        self.limiter = LimiterState::default();
    }
}
