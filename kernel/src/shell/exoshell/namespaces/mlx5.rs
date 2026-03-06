use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

use super::{BoxFuture, ShellNamespace};
use crate::net::drivers::mlx5_registry::{Mlx5SriovStatus, mlx5_disable_vfs, mlx5_enable_vfs, mlx5_sriov_status};
use crate::security::capability::CAP_NET_ADMIN;
use crate::shell::exoshell::types::ExoValue;

pub struct Mlx5Namespace;

impl Mlx5Namespace {
    fn format_bdf(bdf: crate::io::pci::PcieBdf) -> String {
        format!("{:02x}:{:02x}.{}", bdf.bus, bdf.device, bdf.function)
    }

    fn status_value_from_snapshot(status: Mlx5SriovStatus) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(
            String::from("driver_present"),
            ExoValue::Bool(status.driver_present),
        );
        map.insert(
            String::from("bridge_initialized"),
            ExoValue::Bool(status.bridge_initialized),
        );
        map.insert(
            String::from("variant"),
            status
                .variant
                .map(|variant| ExoValue::String(Cow::Owned(String::from(variant.name()))))
                .unwrap_or(ExoValue::Nil),
        );
        map.insert(
            String::from("pf_bdf"),
            status
                .pf_bdf
                .map(|bdf| ExoValue::String(Cow::Owned(Self::format_bdf(bdf))))
                .unwrap_or(ExoValue::Nil),
        );
        map.insert(
            String::from("sriov_supported"),
            ExoValue::Bool(status.sriov_supported),
        );
        map.insert(
            String::from("total_vfs"),
            ExoValue::Int(status.total_vfs as i64),
        );
        map.insert(
            String::from("vf_device_id"),
            status
                .vf_device_id
                .map(|device_id| ExoValue::Int(device_id as i64))
                .unwrap_or(ExoValue::Nil),
        );
        map.insert(
            String::from("active_vfs"),
            ExoValue::Int(status.active_vfs as i64),
        );
        map.insert(
            String::from("vf_bdfs"),
            ExoValue::Array(
                status
                    .vf_bdfs
                    .into_iter()
                    .map(|bdf| ExoValue::String(Cow::Owned(Self::format_bdf(bdf))))
                    .collect(),
            ),
        );
        ExoValue::Map(map)
    }

    fn status() -> ExoValue<'static> {
        Self::status_value_from_snapshot(mlx5_sriov_status())
    }

    fn enable_vfs_with_caps(
        args: &[ExoValue<'static>],
        caps: &crate::security::CapabilitySet,
    ) -> ExoValue<'static> {
        if !caps.has_capability(CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }

        let count = match args.first() {
            Some(ExoValue::Int(n)) if *n > 0 && *n <= u16::MAX as i64 => *n as u16,
            _ => return ExoValue::Error(String::from("usage: mlx5.enable_vfs(count)")),
        };

        match mlx5_enable_vfs(count) {
            Ok(status) => Self::status_value_from_snapshot(status),
            Err(err) => ExoValue::Error(format!("Failed to enable VFs: {}", err)),
        }
    }

    fn disable_vfs_with_caps(caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_NET_ADMIN) {
            return ExoValue::Error(String::from("Permission denied: CAP_NET_ADMIN required"));
        }

        match mlx5_disable_vfs() {
            Ok(status) => Self::status_value_from_snapshot(status),
            Err(err) => ExoValue::Error(format!("Failed to disable VFs: {}", err)),
        }
    }
}

impl ShellNamespace for Mlx5Namespace {
    fn name(&self) -> &str {
        "mlx5"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "status" => Self::status(),
                "enable_vfs" => Self::enable_vfs_with_caps(args, caps),
                "disable_vfs" => Self::disable_vfs_with_caps(caps),
                _ => ExoValue::Error(format!(
                    "Unknown method 'mlx5.{}'. Valid: status, enable_vfs, disable_vfs",
                    method
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::CapabilitySet;
    use alloc::vec::Vec;

    #[test_case]
    fn test_status_map_contains_expected_keys() {
        let value = Mlx5Namespace::status_value_from_snapshot(Mlx5SriovStatus {
            driver_present: true,
            bridge_initialized: true,
            variant: Some(mlx5_driver::ConnectXVariant::CX6),
            pf_bdf: Some(crate::io::pci::PcieBdf::new(0, 2, 0)),
            sriov_supported: true,
            total_vfs: 8,
            vf_device_id: Some(0x101e),
            active_vfs: 2,
            vf_bdfs: Vec::from([
                crate::io::pci::PcieBdf::new(0, 2, 1),
                crate::io::pci::PcieBdf::new(0, 2, 2),
            ]),
        });

        match value {
            ExoValue::Map(map) => {
                assert!(map.contains_key("driver_present"));
                assert!(map.contains_key("bridge_initialized"));
                assert!(map.contains_key("variant"));
                assert!(map.contains_key("pf_bdf"));
                assert!(map.contains_key("sriov_supported"));
                assert!(map.contains_key("total_vfs"));
                assert!(map.contains_key("vf_device_id"));
                assert!(map.contains_key("active_vfs"));
                assert!(map.contains_key("vf_bdfs"));
            }
            _ => panic!("expected status map"),
        }
    }

    #[test_case]
    fn test_enable_vfs_requires_capability() {
        let ns = Mlx5Namespace;
        let caps = CapabilitySet::empty();
        let args = [ExoValue::Int(1)];
        let result = futures::executor::block_on(ns.call("enable_vfs", &args, &caps));

        match result {
            ExoValue::Error(message) => assert!(message.contains("Permission denied")),
            _ => panic!("expected permission error"),
        }
    }

    #[test_case]
    fn test_enable_vfs_validates_arguments() {
        let ns = Mlx5Namespace;
        let caps = CapabilitySet::full();
        let result = futures::executor::block_on(ns.call("enable_vfs", &[], &caps));

        match result {
            ExoValue::Error(message) => assert!(message.contains("usage")),
            _ => panic!("expected argument error"),
        }
    }
}
