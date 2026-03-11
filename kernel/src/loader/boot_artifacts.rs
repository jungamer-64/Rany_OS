// ============================================================================
// kernel/src/loader/boot_artifacts.rs - Boot Artifact Loader
// ============================================================================
//!
//! Loads boot-partition artifacts handed off via `ExoBootInfo`.
//! Driver artifacts under `/drivers` are autostart/staging inputs, while
//! fixture cells under `/cells` remain data-only runtime assets.

use crate::driver_domain;
use crate::driver_domain::RestartPolicy;
use crate::driver_domain::lifecycle::DriverDomainConfig;
use crate::loader::staged_pci::StageArtifactResult;
use alloc::string::String;
use boot_proto::{BootArtifactKind, BootArtifactTable};
use log::{debug, info, warn};

/// Load driver Cells from boot artifact handoff.
///
/// # Returns
/// Number of successfully loaded driver cells
pub fn load_cells_from_boot_artifacts(boot_artifacts: &BootArtifactTable) -> usize {
    if boot_artifacts.is_empty() {
        debug!(target: "boot_artifacts", "No boot artifacts provided");
        return 0;
    }

    info!(
        target: "boot_artifacts",
        "Loading {} boot artifact(s)",
        boot_artifacts.count
    );

    let mut loaded = 0;
    let mut staged = 0;

    for entry in boot_artifacts.entries() {
        let Some(path) = entry.path() else {
            warn!(target: "boot_artifacts", "Skipping artifact with invalid UTF-8 path");
            continue;
        };
        let data = entry.data();

        #[cfg(feature = "qemu-test-export")]
        if entry.kind() == Some(BootArtifactKind::FixtureCell)
            && path.starts_with("cells/")
            && path.ends_with(".cell")
        {
            crate::io::log::early_print("[BOOT_ARTIFACT] fixture cache begin ");
            crate::io::log::early_print(path);
            crate::io::log::early_print("\n");
            crate::driver_domain::qemu_tests::cache_runtime_fixture_cell(path, data);
            crate::io::log::early_print("[BOOT_ARTIFACT] fixture cache done ");
            crate::io::log::early_print(path);
            crate::io::log::early_print("\n");
        }

        if entry.kind() != Some(BootArtifactKind::DriverArtifact)
            || !path.starts_with("drivers/")
            || !path.ends_with(".cell")
        {
            continue;
        }

        info!(
            target: "boot_artifacts",
            "Found driver artifact: {} ({} bytes)",
            path,
            data.len()
        );

        let driver_name = extract_driver_name(path);

        // SAFETY: boot artifact buffers are owned by the bootloader handoff
        // allocation and remain mapped for the kernel lifetime.
        let staged_artifact: &'static [u8] =
            unsafe { core::slice::from_raw_parts(data.as_ptr(), data.len()) };
        match crate::loader::staged_pci::stage_boot_artifact_static(
            &driver_name,
            staged_artifact,
            true,
        ) {
            StageArtifactResult::Staged => {
                info!(
                    target: "boot_artifacts",
                    "Staged PCI driver pack '{}' for later PCI binding",
                    driver_name
                );
                staged += 1;
                continue;
            }
            StageArtifactResult::Rejected(reason) => {
                warn!(target: "boot_artifacts", "Rejected '{}': {}", driver_name, reason);
                continue;
            }
            StageArtifactResult::NotStaged => {}
        }

        let config = DriverDomainConfig::new(driver_name.clone())
            .with_restart_policy(RestartPolicy::on_panic(3, 100))
            .with_capabilities(crate::security::CapabilitySet::empty())
            .with_unsafe_allowed();

        match driver_domain::lifecycle::create_and_start(&config, data) {
            Ok((driver_domain_id, handles)) => {
                let loader_cell_id = driver_domain::driver_domain_manager()
                    .with_cell(driver_domain_id, |c| c.cell_id)
                    .ok()
                    .flatten()
                    .map(|c| c.as_u64());
                info!(
                    target: "boot_artifacts",
                    "Loaded driver cell '{}' as dcell={} loader_cell={:?} handles={}",
                    driver_name,
                    driver_domain_id.as_u64(),
                    loader_cell_id,
                    handles.len()
                );
                loaded += 1;
            }
            Err(e) => {
                warn!(
                    target: "boot_artifacts",
                    "Failed to load driver '{}': {:?}",
                    driver_name,
                    e
                );
            }
        }
    }

    info!(
        target: "boot_artifacts",
        "Loaded {} driver(s) and staged {} PCI driver pack(s) from boot artifacts",
        loaded,
        staged
    );
    loaded
}

/// Extract driver name from path (e.g., "drivers/nvme.cell" -> "nvme")
fn extract_driver_name(path: &str) -> String {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let name = filename.strip_suffix(".cell").unwrap_or(filename);
    String::from(name)
}

#[cfg(test)]
mod tests {
    use super::{extract_driver_name, load_cells_from_boot_artifacts};
    use boot_proto::{BootArtifactEntry, BootArtifactKind, BootArtifactTable};

    #[test_case]
    fn empty_boot_artifact_table_is_noop() {
        assert_eq!(
            load_cells_from_boot_artifacts(&BootArtifactTable::default()),
            0
        );
    }

    #[test_case]
    fn fixture_artifacts_are_not_started_as_driver_cells() {
        let path = b"cells/driver_cell_probe_v1.cell";
        let data = b"fixture";
        let entries = [BootArtifactEntry {
            kind: BootArtifactKind::FixtureCell as u32,
            flags: 0,
            path_ptr: path.as_ptr() as u64,
            path_len: path.len() as u64,
            data_ptr: data.as_ptr() as u64,
            data_len: data.len() as u64,
        }];
        let table = BootArtifactTable {
            entries_ptr: entries.as_ptr() as u64,
            count: entries.len() as u64,
        };

        assert_eq!(load_cells_from_boot_artifacts(&table), 0);
    }

    #[test_case]
    fn extract_driver_name_drops_directory_and_extension() {
        assert_eq!(
            extract_driver_name("drivers/nvme_driver.cell"),
            "nvme_driver"
        );
        assert_eq!(extract_driver_name("plain.cell"), "plain");
    }
}
