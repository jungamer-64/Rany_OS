//! Boot configuration file parser
//!
//! Parses exoloader.cfg configuration file for boot menu entries.
//!
//! Configuration file format:
//! ```text
//! # Comment line
//! timeout=5
//! default=0
//!
//! [RanyOS]
//! kernel=rany_os
//! cmdline=console=serial loglevel=debug
//!
//! [RanyOS (Safe Mode)]
//! kernel=rany_os
//! cmdline=safe_mode no_drivers
//! ```

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Normalized shell launch mode decided during boot handoff.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootShellMode {
    #[default]
    Serial = 0,
    Console = 1,
    Off = 2,
}

/// Boot-critical policy normalized by the bootloader.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BootPolicy {
    pub shell_mode: BootShellMode,
    pub iommu_force: u8,
    pub iommu_scalable: u8,
    pub _reserved: [u8; 5],
}

impl BootPolicy {
    #[must_use]
    pub const fn iommu_force_enabled(self) -> bool {
        self.iommu_force != 0
    }

    #[must_use]
    pub const fn iommu_scalable_enabled(self) -> bool {
        self.iommu_scalable != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootPolicyError {
    IommuDisabledRequested,
    IommuPassthroughRequested,
    DeprecatedIommuGlobalRequested,
}

fn get_cmdline_option<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    for part in cmdline.split_whitespace() {
        let (candidate, value) = part.split_once('=').unwrap_or((part, ""));
        if candidate == key {
            return Some(value);
        }
    }
    None
}

/// Parse boot-critical policy from a merged kernel command line.
pub fn parse_boot_policy(cmdline: &str) -> Result<BootPolicy, BootPolicyError> {
    let mut policy = BootPolicy::default();

    if let Some(shell) = get_cmdline_option(cmdline, "shell") {
        policy.shell_mode = match shell {
            "console" => BootShellMode::Console,
            "serial" => BootShellMode::Serial,
            "off" => BootShellMode::Off,
            _ => BootShellMode::Serial,
        };
    } else if let Some(console) = get_cmdline_option(cmdline, "console") {
        policy.shell_mode = match console {
            "serial" => BootShellMode::Serial,
            _ => BootShellMode::Console,
        };
    }

    if let Some(value) = get_cmdline_option(cmdline, "iommu") {
        match value {
            "off" => return Err(BootPolicyError::IommuDisabledRequested),
            "pt" | "passthrough" => return Err(BootPolicyError::IommuPassthroughRequested),
            "force" => policy.iommu_force = 1,
            _ => {}
        }
    }

    if get_cmdline_option(cmdline, "iommu_global").is_some() {
        return Err(BootPolicyError::DeprecatedIommuGlobalRequested);
    }

    if let Some(value) = get_cmdline_option(cmdline, "iommu_scalable") {
        match value {
            "on" | "1" | "true" => policy.iommu_scalable = 1,
            "off" | "0" | "false" => policy.iommu_scalable = 0,
            _ => {}
        }
    }

    Ok(policy)
}

/// Maximum number of boot entries
pub const MAX_BOOT_ENTRIES: usize = 8;
/// Maximum length of a boot entry name
pub const MAX_NAME_LEN: usize = 64;
/// Maximum length of a path
pub const MAX_PATH_LEN: usize = 128;
/// Maximum length of command line
pub const MAX_CMDLINE_LEN: usize = 256;

/// A boot menu entry
#[derive(Debug, Clone)]
pub struct BootEntry {
    /// Display name for the entry
    pub name: String,
    /// Kernel file path
    pub kernel: String,
    /// Optional kernel command line
    pub cmdline: Option<String>,
}

impl Default for BootEntry {
    fn default() -> Self {
        Self {
            name: String::new(),
            kernel: String::new(),
            cmdline: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootConfigError {
    DeprecatedKey(&'static str),
}

/// Boot configuration
#[derive(Debug, Clone)]
pub struct BootConfig {
    /// Timeout in seconds before booting default entry (0 = no timeout)
    pub timeout: u32,
    /// Index of default boot entry
    pub default_entry: usize,
    /// Boot entries
    pub entries: Vec<BootEntry>,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            timeout: 5,
            default_entry: 0,
            entries: Vec::new(),
        }
    }
}

/// Save a boot entry to config if it has a non-empty kernel path
fn save_entry_if_valid(config: &mut BootConfig, entry: Option<BootEntry>) {
    if let Some(entry) = entry {
        if !entry.kernel.is_empty() {
            config.entries.push(entry);
        }
    }
}

/// Apply a global setting (before any section) to the config
fn apply_global_setting(config: &mut BootConfig, key: &str, value: &str) {
    match key {
        "timeout" => {
            if let Ok(t) = value.parse::<u32>() {
                config.timeout = t;
            }
        }
        "default" => {
            if let Ok(d) = value.parse::<usize>() {
                config.default_entry = d;
            }
        }
        _ => {}
    }
}

/// Apply an entry-specific setting
fn apply_entry_setting(
    entry: &mut BootEntry,
    key: &str,
    value: &str,
) -> Result<(), BootConfigError> {
    match key {
        "kernel" => entry.kernel = String::from(value),
        "initramfs" => return Err(BootConfigError::DeprecatedKey("initramfs")),
        "cmdline" => entry.cmdline = Some(String::from(value)),
        _ => {}
    }
    Ok(())
}

/// Process a single configuration line, updating global config or current entry.
fn process_config_line(
    config: &mut BootConfig,
    current_entry: &mut Option<BootEntry>,
    line: &str,
) -> Result<(), BootConfigError> {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }

    if line.starts_with('[') && line.ends_with(']') {
        save_entry_if_valid(config, current_entry.take());
        let name = &line[1..line.len() - 1];
        let mut entry = BootEntry::default();
        entry.name = String::from(name);
        *current_entry = Some(entry);
        return Ok(());
    }

    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim();

        if current_entry.is_none() {
            apply_global_setting(config, key, value);
        } else if let Some(entry) = current_entry {
            apply_entry_setting(entry, key, value)?;
        }
    }
    Ok(())
}

/// Parse boot configuration from file contents
///
/// # Arguments
/// * `text` - UTF-8 configuration file contents as string
///
/// # Returns
/// Parsed BootConfig, or an error for deprecated/invalid breaking config keys.
pub fn parse_config(text: &str) -> Result<BootConfig, BootConfigError> {
    let mut config = BootConfig::default();
    let mut current_entry: Option<BootEntry> = None;

    for line in text.lines() {
        process_config_line(&mut config, &mut current_entry, line)?;
    }

    save_entry_if_valid(&mut config, current_entry);

    if config.default_entry >= config.entries.len() && !config.entries.is_empty() {
        config.default_entry = 0;
    }

    Ok(config)
}

/// Create default configuration when no config file exists
pub fn default_config() -> BootConfig {
    let mut config = BootConfig::default();

    // Add default RanyOS entry
    config.entries.push(BootEntry {
        name: String::from("RanyOS"),
        kernel: String::from("rany_os"),
        cmdline: None,
    });

    config
}

#[cfg(test)]
mod tests {
    use super::{
        BootConfigError, BootPolicy, BootPolicyError, BootShellMode, default_config,
        parse_boot_policy, parse_config,
    };

    #[test]
    fn parse_basic_config_smoke() {
        let cfg = parse_config("timeout=5\n[Default]\nkernel=rany_os\n").expect("valid config");
        assert_eq!(cfg.timeout, 5);
        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].kernel, "rany_os");
    }

    #[test]
    fn parse_extended_config_smoke() {
        let empty_cfg = parse_config("").expect("empty config is valid");
        assert!(empty_cfg.entries.is_empty());

        let basic_cfg = parse_config("timeout=10\ndefault=1\n\n[Test]\nkernel=test_kernel\n")
            .expect("valid config");
        assert_eq!(basic_cfg.timeout, 10);
        assert_eq!(basic_cfg.default_entry, 0);
        assert_eq!(basic_cfg.entries.len(), 1);
        assert_eq!(basic_cfg.entries[0].name, "Test");

        let fallback = default_config();
        assert!(!fallback.entries.is_empty());
        assert_eq!(fallback.entries[0].kernel, "rany_os");
    }

    #[test]
    fn parse_config_rejects_deprecated_initramfs_key() {
        let err = parse_config("[Default]\nkernel=rany_os\ninitramfs=initramfs.tar\n")
            .expect_err("deprecated initramfs key must fail");
        assert_eq!(err, BootConfigError::DeprecatedKey("initramfs"));
    }

    #[test]
    fn boot_policy_defaults_to_serial_and_iommu_defaults() {
        assert_eq!(
            parse_boot_policy("").expect("empty cmdline is valid"),
            BootPolicy::default()
        );
    }

    #[test]
    fn boot_policy_parses_shell_modes() {
        assert_eq!(
            parse_boot_policy("shell=console")
                .expect("shell=console should parse")
                .shell_mode,
            BootShellMode::Console
        );
        assert_eq!(
            parse_boot_policy("shell=serial")
                .expect("shell=serial should parse")
                .shell_mode,
            BootShellMode::Serial
        );
        assert_eq!(
            parse_boot_policy("shell=off")
                .expect("shell=off should parse")
                .shell_mode,
            BootShellMode::Off
        );
    }

    #[test]
    fn boot_policy_console_compat_is_supported() {
        assert_eq!(
            parse_boot_policy("console=serial")
                .expect("console=serial should parse")
                .shell_mode,
            BootShellMode::Serial
        );
        assert_eq!(
            parse_boot_policy("console=tty0")
                .expect("console=tty0 should parse")
                .shell_mode,
            BootShellMode::Console
        );
    }

    #[test]
    fn boot_policy_parses_iommu_flags() {
        let policy = parse_boot_policy("iommu=force iommu_scalable=on")
            .expect("iommu force/scalable should parse");
        assert!(policy.iommu_force_enabled());
        assert!(policy.iommu_scalable_enabled());

        let policy =
            parse_boot_policy("iommu_scalable=off").expect("iommu_scalable=off should parse");
        assert!(!policy.iommu_force_enabled());
        assert!(!policy.iommu_scalable_enabled());
    }

    #[test]
    fn boot_policy_rejects_iommu_disable_and_passthrough() {
        assert_eq!(
            parse_boot_policy("iommu=off"),
            Err(BootPolicyError::IommuDisabledRequested)
        );
        assert_eq!(
            parse_boot_policy("iommu=pt"),
            Err(BootPolicyError::IommuPassthroughRequested)
        );
        assert_eq!(
            parse_boot_policy("iommu=passthrough"),
            Err(BootPolicyError::IommuPassthroughRequested)
        );
    }

    #[test]
    fn boot_policy_rejects_deprecated_iommu_global() {
        assert_eq!(
            parse_boot_policy("console=serial iommu_global=1"),
            Err(BootPolicyError::DeprecatedIommuGlobalRequested)
        );
    }
}
