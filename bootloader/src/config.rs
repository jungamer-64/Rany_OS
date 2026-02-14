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
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Check for section header [Name]
        if line.starts_with('[') && line.ends_with(']') {
            // Save previous entry if any
            if let Some(entry) = current_entry.take() {
                if !entry.kernel.is_empty() {
                    config.entries.push(entry);
                }
            }

            // Start new entry
            let name = &line[1..line.len() - 1];
            let mut entry = BootEntry::default();
            entry.name = String::from(name);
            current_entry = Some(entry);
            continue;
        }

        // Parse key=value pairs
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();

            // Global settings (before any section)
            if current_entry.is_none() {
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
            } else if let Some(ref mut entry) = current_entry {
                // Entry-specific settings
                match key {
                    "kernel" => entry.kernel = String::from(value),
                    "initramfs" => entry.initramfs = Some(String::from(value)),
                    "cmdline" => entry.cmdline = Some(String::from(value)),
                    _ => {}
                }
            }
        }
    }

    // Save last entry
    if let Some(entry) = current_entry {
        if !entry.kernel.is_empty() {
            config.entries.push(entry);
        }
    }

    // Validate default entry index
    if config.default_entry >= config.entries.len() && !config.entries.is_empty() {
        config.default_entry = 0;
    }

    config
}

/// Create default configuration when no config file exists
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let config = parse_config(b"");
        assert_eq!(config.entries.len(), 0);
    }

    #[test]
    fn test_parse_basic() {
        let data = b"timeout=10\ndefault=1\n\n[Test]\nkernel=test_kernel\n";
        let config = parse_config(data);
        assert_eq!(config.timeout, 10);
        assert_eq!(config.entries.len(), 1);
        assert_eq!(config.entries[0].name, "Test");
    }
}

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests {
    use super::parse_config;

    pub fn parse_smoke() -> bool {
        let cfg = parse_config("timeout=9\n[Main]\nkernel=rany_os\n");
        cfg.timeout == 9 && cfg.entries.len() == 1 && cfg.entries[0].name == "Main"
    }
}
