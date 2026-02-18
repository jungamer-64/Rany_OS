//! Boot configuration file parser
//!
//! Parses exoloader.cfg configuration file for boot menu entries.
//!
//! Configuration file format:
//! ```
//! # Comment line
//! timeout=5
//! default=0
//!
//! [RanyOS]
//! kernel=rany_os
//! initramfs=initramfs.tar
//! cmdline=console=serial loglevel=debug
//!
//! [RanyOS (Safe Mode)]
//! kernel=rany_os
//! cmdline=safe_mode no_drivers
//! ```

use alloc::string::String;
use alloc::vec::Vec;

/// Maximum number of boot entries
#[allow(dead_code)]
pub const MAX_BOOT_ENTRIES: usize = 8;
/// Maximum length of a boot entry name
#[allow(dead_code)]
pub const MAX_NAME_LEN: usize = 64;
/// Maximum length of a path
#[allow(dead_code)]
pub const MAX_PATH_LEN: usize = 128;
/// Maximum length of command line
#[allow(dead_code)]
pub const MAX_CMDLINE_LEN: usize = 256;

/// A boot menu entry
#[derive(Clone)]
pub struct BootEntry {
    /// Display name for the entry
    pub name: String,
    /// Kernel file path
    pub kernel: String,
    /// Optional initramfs file path
    pub initramfs: Option<String>,
    /// Optional kernel command line
    pub cmdline: Option<String>,
}

impl Default for BootEntry {
    fn default() -> Self {
        Self {
            name: String::new(),
            kernel: String::new(),
            initramfs: None,
            cmdline: None,
        }
    }
}

/// Boot configuration
#[derive(Clone)]
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
fn apply_entry_setting(entry: &mut BootEntry, key: &str, value: &str) {
    match key {
        "kernel" => entry.kernel = String::from(value),
        "initramfs" => entry.initramfs = Some(String::from(value)),
        "cmdline" => entry.cmdline = Some(String::from(value)),
        _ => {}
    }
}

/// Process a single configuration line, updating global config or current entry.
fn process_config_line(
    config: &mut BootConfig,
    current_entry: &mut Option<BootEntry>,
    line: &str,
) {
    let line = line.trim();

    if line.is_empty() || line.starts_with('#') {
        return;
    }

    if line.starts_with('[') && line.ends_with(']') {
        save_entry_if_valid(config, current_entry.take());
        let name = &line[1..line.len() - 1];
        let mut entry = BootEntry::default();
        entry.name = String::from(name);
        *current_entry = Some(entry);
        return;
    }

    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim();

        if current_entry.is_none() {
            apply_global_setting(config, key, value);
        } else if let Some(entry) = current_entry {
            apply_entry_setting(entry, key, value);
        }
    }
}

/// Parse boot configuration from file contents
///
/// # Arguments
/// * `text` - UTF-8 configuration file contents as string
///
/// # Returns
/// Parsed BootConfig, or default config if parsing fails
pub fn parse_config(text: &str) -> BootConfig {
    let mut config = BootConfig::default();
    let mut current_entry: Option<BootEntry> = None;

    for line in text.lines() {
        process_config_line(&mut config, &mut current_entry, line);
    }

    save_entry_if_valid(&mut config, current_entry);

    if config.default_entry >= config.entries.len() && !config.entries.is_empty() {
        config.default_entry = 0;
    }

    config
}

/// Create default configuration when no config file exists
#[allow(dead_code)]
pub fn default_config() -> BootConfig {
    let mut config = BootConfig::default();

    // Add default RanyOS entry
    config.entries.push(BootEntry {
        name: String::from("RanyOS"),
        kernel: String::from("rany_os"),
        initramfs: Some(String::from("initramfs.tar")),
        cmdline: None,
    });

    config
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::parse_config;

    pub fn parse_smoke() -> bool {
        let cfg = parse_config("timeout=9\n[Main]\nkernel=rany_os\n");
        cfg.timeout == 9 && cfg.entries.len() == 1 && cfg.entries[0].name == "Main"
    }

    pub fn parse_empty_smoke() -> bool {
        let config = parse_config("");
        config.entries.is_empty()
    }

    pub fn parse_basic_smoke() -> bool {
        let config = parse_config("timeout=10\ndefault=1\n\n[Test]\nkernel=test_kernel\n");
        config.timeout == 10 && config.entries.len() == 1 && config.entries[0].name == "Test"
    }
}
