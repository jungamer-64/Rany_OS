use super::{PcieBdf, PcieConfig, PcieError, PcieResult, acs_regs, ext_cap_id};

/// ACS Capability structure
#[derive(Debug, Clone)]
pub struct AcsCapability {
    pub offset: u16,
    pub source_validation: bool,
    pub translation_blocking: bool,
    pub p2p_request_redirect: bool,
    pub p2p_completion_redirect: bool,
    pub upstream_forwarding: bool,
    pub p2p_egress_control: bool,
    pub direct_translated_p2p: bool,
}

/// ACS Controller
pub struct AcsController {
    config: &'static PcieConfig,
    bdf: PcieBdf,
    capability: Option<AcsCapability>,
}

impl AcsController {
    pub fn new(config: &'static PcieConfig, bdf: PcieBdf) -> PcieResult<Self> {
        let offset = config
            .find_ext_capability(bdf, ext_cap_id::ACS)
            .ok_or(PcieError::CapabilityNotFound)?;

        let cap_reg = config
            .read16(bdf, offset + acs_regs::CAP)
            .ok_or(PcieError::ConfigError)?;

        Ok(Self {
            config,
            bdf,
            capability: Some(AcsCapability {
                offset,
                source_validation: (cap_reg & 0x01) != 0,
                translation_blocking: (cap_reg & 0x02) != 0,
                p2p_request_redirect: (cap_reg & 0x04) != 0,
                p2p_completion_redirect: (cap_reg & 0x08) != 0,
                upstream_forwarding: (cap_reg & 0x10) != 0,
                p2p_egress_control: (cap_reg & 0x20) != 0,
                direct_translated_p2p: (cap_reg & 0x40) != 0,
            }),
        })
    }

    /// Enable ACS P2P Isolation (Source Validation, Translation Blocking, P2P Redirect, Upstream Forwarding)
    pub fn enable_isolation(&self) -> PcieResult<()> {
        let cap = self
            .capability
            .as_ref()
            .ok_or(PcieError::CapabilityNotFound)?;
        let offset = cap.offset;

        let mut ctrl = self
            .config
            .read16(self.bdf, offset + acs_regs::CTRL)
            .ok_or(PcieError::ConfigError)?;

        // Enable Source Validation (SV) if supported
        if cap.source_validation {
            ctrl |= 0x01;
        }
        // Enable Translation Blocking (TB) if supported
        // SECURITY: TB is critical to prevent devices from bypassing IOMMU via 'Translated' TLP headers
        if cap.translation_blocking {
            ctrl |= 0x02;
        }
        // Enable P2P Request Redirect (RR) if supported
        if cap.p2p_request_redirect {
            ctrl |= 0x04;
        }
        // Enable P2P Completion Redirect (CR) if supported
        if cap.p2p_completion_redirect {
            ctrl |= 0x08;
        }
        // Enable Upstream Forwarding (UF) if supported
        if cap.upstream_forwarding {
            ctrl |= 0x10;
        }

        self.config
            .write16(self.bdf, offset + acs_regs::CTRL, ctrl)
            .ok_or(PcieError::ConfigError)?;

        Ok(())
    }

    /// Check if ACS isolation is enabled (strict check for IOMMU grouping)
    pub fn is_isolation_enabled(&self) -> bool {
        let Some(cap) = self.capability.as_ref() else {
            return false;
        };

        let Some(ctrl) = self.config.read16(self.bdf, cap.offset + acs_regs::CTRL) else {
            return false;
        };

        // Strict security policy:
        // For a bridge to provide isolation, it MUST support and enable:
        // 1. Source Validation (SV): Prevents device spoofing of requester IDs.
        // 2. Translation Blocking (TB): Prevents bypass via Translated TLPs.
        // 3. P2P Request Redirect (RR): Forces P2P requests to go upstream to IOMMU.
        // 4. P2P Completion Redirect (CR): Forces P2P completions to go upstream.
        // 5. Upstream Forwarding (UF): Prevents direct P2P bypass of IOMMU.

        let sv_ok = cap.source_validation && (ctrl & 0x01) != 0;
        let tb_ok = !cap.translation_blocking || (ctrl & 0x02) != 0; // Required IF supported
        let rr_ok = cap.p2p_request_redirect && (ctrl & 0x04) != 0;
        let cr_ok = cap.p2p_completion_redirect && (ctrl & 0x08) != 0;
        let uf_ok = cap.upstream_forwarding && (ctrl & 0x10) != 0;

        sv_ok && tb_ok && rr_ok && cr_ok && uf_ok
    }
}

/// Check if a device supports ACS
pub fn device_supports_acs(config: &PcieConfig, bdf: PcieBdf) -> bool {
    config.find_ext_capability(bdf, ext_cap_id::ACS).is_some()
}
