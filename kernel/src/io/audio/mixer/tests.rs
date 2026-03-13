use super::*;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mixer_creation() {
    let mixer = Mixer::default_mixer();
    assert_eq!(mixer.active_channels(), 0);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_add_channel() {
    let mut mixer = Mixer::default_mixer();
    let id = mixer.add_channel(ChannelConfig::default()).unwrap();
    assert!(id > 0);
    assert_eq!(mixer.active_channels(), 1);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_volume_control() {
    let mut mixer = Mixer::default_mixer();
    let id = mixer.add_channel(ChannelConfig::default()).unwrap();
    mixer.set_volume(id, 0.5).unwrap();
    let config = mixer.get_channel_config(id).unwrap();
    assert!((config.volume - 0.5).abs() < 0.001);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_pan_control() {
    let mut mixer = Mixer::default_mixer();
    let id = mixer.add_channel(ChannelConfig::default()).unwrap();
    mixer.set_pan(id, -0.5).unwrap();
    let config = mixer.get_channel_config(id).unwrap();
    assert!((config.pan - (-0.5)).abs() < 0.001);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mono_to_stereo() {
    let mono = vec![0.5, -0.5, 0.25];
    let stereo = Mixer::mono_to_stereo(&mono);
    assert_eq!(stereo.len(), 6);
    assert_eq!(stereo, vec![0.5, 0.5, -0.5, -0.5, 0.25, 0.25]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_limiter_soft_clip() {
    let mut mixer = Mixer::default_mixer();
    mixer.output_buffer = vec![1.5, -1.5, 0.5, -0.5];
    let mut buffer_copy = mixer.output_buffer.clone();
    Mixer::apply_limiter_to_buffer(
        &mut mixer.limiter,
        mixer.config.limiter_enabled,
        &mut buffer_copy,
    );
    // All samples should be within -1.0 to 1.0
    for sample in &buffer_copy {
        assert!(*sample >= -1.0 && *sample <= 1.0);
    }
}
