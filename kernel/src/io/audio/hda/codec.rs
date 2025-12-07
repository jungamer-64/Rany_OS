// ============================================================================
// src/io/audio/hda/codec.rs - Codec Detection and Configuration
// ============================================================================
//!
//! HDA コーデックの検出と設定。
//!
//! - コーデック検出
//! - ノード列挙
//! - オーディオ出力設定

#![allow(dead_code)]

use alloc::vec::Vec;

use super::controller::HdaController;
use super::regs::*;
use super::types::{CodecInfo, HdaError, HdaResult, NodeType, WidgetCaps};

// ============================================================================
// Codec Detection
// ============================================================================

/// Detect connected codecs
pub fn detect_codecs(controller: &mut HdaController) -> HdaResult<()> {
    crate::log!("[HDA] Detecting codecs...\n");

    let statests = controller.read16(REG_STATESTS);

    for codec_addr in 0..15 {
        if (statests & (1 << codec_addr)) != 0 {
            crate::log!("[HDA] Codec found at address {}\n", codec_addr);

            // Read vendor/device ID
            let vendor_id = controller.get_parameter(codec_addr as u8, 0, PARAM_VENDOR_ID)?;
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

            controller.codecs.push(codec);
        }
    }

    if controller.codecs.is_empty() {
        return Err(HdaError::NoCodec);
    }

    // Clear state change status
    controller.write16(REG_STATESTS, statests);

    Ok(())
}

/// Initialize detected codecs
pub fn init_codecs(controller: &mut HdaController) -> HdaResult<()> {
    for i in 0..controller.codecs.len() {
        let codec_addr = controller.codecs[i].address;
        enumerate_codec(controller, codec_addr)?;
    }

    Ok(())
}

/// Enumerate codec nodes
fn enumerate_codec(controller: &mut HdaController, codec_addr: u8) -> HdaResult<()> {
    crate::log!("[HDA] Enumerating codec {}...\n", codec_addr);

    // Get subordinate node count from root node (node 0)
    let sub_nodes = controller.get_parameter(codec_addr, 0, PARAM_SUB_NODE_COUNT)?;
    let start_node = ((sub_nodes >> 16) & 0xFF) as u8;
    let num_nodes = (sub_nodes & 0xFF) as u8;

    crate::log!(
        "[HDA] Root node: start={}, count={}\n",
        start_node,
        num_nodes
    );

    // Look for Audio Function Group
    for node_id in start_node..(start_node + num_nodes) {
        let func_type = controller.get_parameter(codec_addr, node_id, PARAM_FUNC_GROUP_TYPE)?;
        let node_type = func_type & 0xFF;

        crate::log!(
            "[HDA] Node {}: type={}\n",
            node_id,
            if node_type == 1 { "AFG" } else { "other" }
        );

        if node_type == 0x01 {
            // Audio Function Group
            // Find codec in our list
            if let Some(codec) = controller.codecs.iter_mut().find(|c| c.address == codec_addr) {
                codec.afg_node = Some(node_id);
            }

            // Enumerate AFG sub-nodes
            enumerate_afg(controller, codec_addr, node_id)?;
        }
    }

    Ok(())
}

/// Enumerate Audio Function Group nodes
fn enumerate_afg(controller: &mut HdaController, codec_addr: u8, afg_node: u8) -> HdaResult<()> {
    // Power up the AFG
    controller.send_command(codec_addr, afg_node, VERB_SET_POWER | POWER_D0 as u32)?;
    HdaController::delay_us(10000); // Wait for power up

    // Get subordinate nodes
    let sub_nodes = controller.get_parameter(codec_addr, afg_node, PARAM_SUB_NODE_COUNT)?;
    let start_node = ((sub_nodes >> 16) & 0xFF) as u8;
    let num_nodes = (sub_nodes & 0xFF) as u8;

    crate::log!(
        "[HDA] AFG {}: widgets {}..{}\n",
        afg_node,
        start_node,
        start_node + num_nodes - 1
    );

    for node_id in start_node..(start_node + num_nodes) {
        let caps = controller.get_parameter(codec_addr, node_id, PARAM_WIDGET_CAPS)?;
        let widget_caps = WidgetCaps::from(caps);

        crate::log!(
            "[HDA] Widget {}: {:?}\n",
            node_id,
            widget_caps.widget_type
        );

        // Find codec and add node to appropriate list
        if let Some(codec) = controller.codecs.iter_mut().find(|c| c.address == codec_addr) {
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

// ============================================================================
// Codec Output Configuration
// ============================================================================

/// Configure codec for audio output
pub fn configure_codec_output(
    controller: &HdaController,
    codec_addr: u8,
    stream_num: u8,
) -> HdaResult<()> {
    let codec = controller
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
    controller.send_command(codec_addr, dac_node, VERB_SET_POWER | POWER_D0 as u32)?;
    HdaController::delay_us(1000);

    // Set stream/channel assignment
    // Stream number in upper 4 bits, channel in lower 4 bits
    let stream_chan = ((stream_num as u32) << 4) | 0; // Stream N, Channel 0
    controller.send_command(codec_addr, dac_node, VERB_SET_CONV_STREAM | stream_chan)?;

    // Set converter format (48kHz, 16-bit, stereo)
    let format = 0x0011; // 48kHz, 16-bit, 2 channels
    controller.send_command(codec_addr, dac_node, VERB_SET_CONV_FMT | format)?;

    // Unmute DAC output amplifier
    let amp_val = AMP_SET_OUTPUT | AMP_SET_LEFT | AMP_SET_RIGHT | 0x7F; // Max gain
    controller.send_command(codec_addr, dac_node, VERB_SET_AMP_GAIN | amp_val as u32)?;

    // Power up pin
    controller.send_command(codec_addr, pin_node, VERB_SET_POWER | POWER_D0 as u32)?;
    HdaController::delay_us(1000);

    // Enable pin output
    controller.send_command(
        codec_addr,
        pin_node,
        VERB_SET_PIN_CTL | PIN_CTL_OUT_EN as u32,
    )?;

    // Enable EAPD if available (for external amplifier)
    controller.send_command(codec_addr, pin_node, VERB_SET_EAPD | EAPD_EAPD as u32)?;

    // Unmute pin output amplifier
    controller.send_command(codec_addr, pin_node, VERB_SET_AMP_GAIN | amp_val as u32)?;

    crate::log!("[HDA] Codec output configured\n");
    Ok(())
}
