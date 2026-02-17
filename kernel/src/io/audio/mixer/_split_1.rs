use super::*;


// ============================================================================
// Math Approximations (for no_std)
// ============================================================================

/// Sine approximation using Taylor series
/// Good for angles 0 to π/2
pub(crate) fn sin_approx(x: f32) -> f32 {
    // Taylor series: sin(x) ≈ x - x³/6 + x⁵/120 - x⁷/5040
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    let x7 = x5 * x2;
    x - x3 / 6.0 + x5 / 120.0 - x7 / 5040.0
}

/// Cosine approximation using Taylor series
/// Good for angles 0 to π/2
pub(crate) fn cos_approx(x: f32) -> f32 {
    // Taylor series: cos(x) ≈ 1 - x²/2 + x⁴/24 - x⁶/720
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    1.0 - x2 / 2.0 + x4 / 24.0 - x6 / 720.0
}

// ============================================================================
// Global Mixer Instance
// ============================================================================

use spin::Mutex;

pub(crate) static GLOBAL_MIXER: Mutex<Option<Mixer>> = Mutex::new(None);

/// グローバルミキサーを初期化
pub fn init() {
    let mut mixer = GLOBAL_MIXER.lock();
    if mixer.is_none() {
        *mixer = Some(Mixer::default_mixer());
    }
}

/// グローバルミキサーにアクセス
pub fn with_mixer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&Mixer) -> R,
{
    GLOBAL_MIXER.lock().as_ref().map(f)
}

/// グローバルミキサーに可変アクセス
pub fn with_mixer_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Mixer) -> R,
{
    GLOBAL_MIXER.lock().as_mut().map(f)
}

/// チャンネルを追加
pub fn add_channel(config: ChannelConfig) -> MixerResult<u64> {
    with_mixer_mut(|m| m.add_channel(config)).unwrap_or(Err(MixerError::InvalidParameter(
        "Mixer not initialized".into(),
    )))
}

/// サンプルを送信（i16形式）
pub fn submit_i16(channel_id: u64, samples: &[i16]) -> MixerResult<()> {
    with_mixer_mut(|m| m.submit_samples_i16(channel_id, samples)).unwrap_or(Err(
        MixerError::InvalidParameter("Mixer not initialized".into()),
    ))
}

/// ミックス出力を取得（i16形式）
pub fn mix_output_i16() -> Vec<i16> {
    with_mixer_mut(|m| m.mix_to_i16()).unwrap_or_default()
}

// ============================================================================
// Tests (when std is available)
// ============================================================================

#[cfg(test)]
mod tests;

