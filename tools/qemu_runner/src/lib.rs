mod qmp;

pub use qmp::QmpError;

use std::fmt;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use qmp::{DeviceDeleteOutcome, HotpluggedCpu, QmpClient};

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub profile: String,
    pub case_filter: Option<String>,
    pub timeout_secs: u64,
    pub memory_mb: u64,
    pub smp: u16,
    pub max_cpus: u16,
    pub cpu: String,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuHotplugMode {
    Lifecycle,
    Sparse,
}

fn cpu_hotplug_mode(profile: &str) -> Option<CpuHotplugMode> {
    match profile {
        "cpu-hotplug" => Some(CpuHotplugMode::Lifecycle),
        "cpu-hotplug-sparse" => Some(CpuHotplugMode::Sparse),
        _ => None,
    }
}

fn iommu_device_arg(profile: &str) -> &'static str {
    if matches!(cpu_hotplug_mode(profile), Some(CpuHotplugMode::Sparse)) {
        "intel-iommu,intremap=on,eim=on,caching-mode=on,device-iotlb=on"
    } else {
        "intel-iommu,intremap=on,caching-mode=on,device-iotlb=on"
    }
}

impl RunConfig {
    #[must_use]
    pub fn for_profile(profile: impl Into<String>) -> Self {
        let profile = profile.into();
        let (smp, max_cpus) = match cpu_hotplug_mode(&profile) {
            Some(CpuHotplugMode::Lifecycle) => (1, 2),
            Some(CpuHotplugMode::Sparse) => (1, 256),
            None => (2, 2),
        };
        let cpu = if matches!(cpu_hotplug_mode(&profile), Some(CpuHotplugMode::Sparse)) {
            String::from("qemu64,+x2apic,+rdtscp,+rdrand")
        } else {
            String::from("qemu64,+rdtscp,+rdrand")
        };
        Self {
            profile,
            case_filter: None,
            timeout_secs: 120,
            memory_mb: 1024,
            smp,
            max_cpus,
            cpu,
            extra_args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub profile: String,
    pub artifact_path: PathBuf,
    pub log_path: PathBuf,
    pub qemu_stderr_path: PathBuf,
    pub host_exit_code: i32,
    pub isa_debug_value: Option<u32>,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub struct PackagedImage {
    pub boot_root: PathBuf,
    pub kernel_payload_path: PathBuf,
}

const STORAGE_TEST_DISK_SECTOR_SIZE: usize = 512;
const STORAGE_TEST_DISK_TOTAL_SECTORS: u32 = 4096;

#[derive(Debug)]
pub enum BuildError {
    CargoLaunch {
        step: &'static str,
        source: std::io::Error,
    },
    CargoFailed {
        step: &'static str,
        exit_code: i32,
    },
    CommandLaunch {
        step: &'static str,
        program: String,
        source: std::io::Error,
    },
    CommandFailed {
        step: &'static str,
        program: String,
        exit_code: i32,
    },
    ArtifactMissing {
        step: &'static str,
        path: PathBuf,
    },
    Io {
        step: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CargoLaunch { step, source } => {
                write!(f, "failed to launch cargo for {step}: {source}")
            }
            Self::CargoFailed { step, exit_code } => {
                write!(f, "cargo step '{step}' failed with exit code {exit_code}")
            }
            Self::CommandLaunch {
                step,
                program,
                source,
            } => {
                write!(f, "failed to launch {program} for {step}: {source}")
            }
            Self::CommandFailed {
                step,
                program,
                exit_code,
            } => {
                write!(
                    f,
                    "{program} step '{step}' failed with exit code {exit_code}"
                )
            }
            Self::ArtifactMissing { step, path } => {
                write!(f, "artifact missing after {step}: {}", path.display())
            }
            Self::Io { step, source } => {
                write!(f, "I/O error during {step}: {source}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Debug)]
pub enum RunError {
    Build(Box<BuildError>),
    QemuNotFound(Box<str>),
    FirmwareMissing(Box<str>),
    InvalidAccel(Box<str>),
    AccelUnavailable(Box<str>),
    InvalidCpuTopology {
        initial_cpus: u16,
        max_cpus: u16,
    },
    QemuLaunch(std::io::Error),
    Qmp {
        source: Box<QmpError>,
        log_path: Box<PathBuf>,
        qemu_stderr_path: Box<PathBuf>,
    },
    Timeout {
        timeout_secs: u64,
        log_path: Box<PathBuf>,
        qemu_stderr_path: Box<PathBuf>,
    },
    ProfileFailed(Box<RunReport>),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(err) => write!(f, "build failed: {err}"),
            Self::QemuNotFound(msg) => write!(f, "{msg}"),
            Self::FirmwareMissing(msg) => write!(f, "{msg}"),
            Self::InvalidAccel(msg) => write!(f, "{msg}"),
            Self::AccelUnavailable(msg) => write!(f, "{msg}"),
            Self::InvalidCpuTopology {
                initial_cpus,
                max_cpus,
            } => write!(
                f,
                "invalid CPU topology: initial CPUs must be in 1..={max_cpus}, max CPUs must be at most 256 (got initial={initial_cpus}, max={max_cpus})"
            ),
            Self::QemuLaunch(err) => write!(f, "failed to launch qemu-system-x86_64: {err}"),
            Self::Qmp {
                source,
                log_path,
                qemu_stderr_path,
            } => write!(
                f,
                "CPU hotplug QMP protocol failed: {source} (serial log: {}, qemu stderr log: {})",
                log_path.display(),
                qemu_stderr_path.display()
            ),
            Self::Timeout {
                timeout_secs,
                log_path,
                qemu_stderr_path,
            } => write!(
                f,
                "full-boot profile timed out after {timeout_secs}s (serial log: {}, qemu stderr log: {})",
                log_path.display(),
                qemu_stderr_path.display()
            ),
            Self::ProfileFailed(report) => write!(
                f,
                "full-boot profile '{}' failed (host exit: {}, serial log: {}, qemu stderr log: {})",
                report.profile,
                report.host_exit_code,
                report.log_path.display(),
                report.qemu_stderr_path.display()
            ),
        }
    }
}

impl std::error::Error for RunError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccelPreference {
    Auto,
    Kvm,
    Tcg,
}

impl AccelPreference {
    fn parse(raw: Option<&str>) -> Result<Self, RunError> {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::Auto),
            Some(value) if value.eq_ignore_ascii_case("auto") => Ok(Self::Auto),
            Some(value) if value.eq_ignore_ascii_case("kvm") => Ok(Self::Kvm),
            Some(value) if value.eq_ignore_ascii_case("tcg") => Ok(Self::Tcg),
            Some(value) => Err(RunError::InvalidAccel(
                format!("unsupported QEMU_TEST_ACCEL='{value}'. Expected one of: auto, kvm, tcg.")
                    .into_boxed_str(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FullbootAccel {
    Kvm,
    Tcg,
}

impl FullbootAccel {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Tcg => "tcg",
        }
    }
}

const fn machine_arg_for_accel(accel: FullbootAccel) -> &'static str {
    match accel {
        FullbootAccel::Kvm => "q35,kernel-irqchip=split",
        FullbootAccel::Tcg => "q35",
    }
}

#[must_use]
pub const fn normalize_qemu_exit_code(host_exit_code: i32) -> Option<u32> {
    match host_exit_code {
        33 => Some(0x10),
        35 => Some(0x11),
        _ => None,
    }
}

#[must_use]
pub fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap_or_else(|_| manifest_dir.join("..").join(".."))
}

fn run_cargo(root: &Path, step: &'static str, args: &[&str]) -> Result<(), BuildError> {
    let status = Command::new("cargo")
        .current_dir(root)
        .args(args)
        .status()
        .map_err(|source| BuildError::CargoLaunch { step, source })?;

    if status.success() {
        return Ok(());
    }

    Err(BuildError::CargoFailed {
        step,
        exit_code: status.code().unwrap_or(-1),
    })
}

fn run_command(
    root: &Path,
    step: &'static str,
    program: &str,
    args: &[&str],
) -> Result<(), BuildError> {
    let status = Command::new(program)
        .current_dir(root)
        .args(args)
        .status()
        .map_err(|source| BuildError::CommandLaunch {
            step,
            program: program.to_string(),
            source,
        })?;

    if status.success() {
        return Ok(());
    }

    Err(BuildError::CommandFailed {
        step,
        program: program.to_string(),
        exit_code: status.code().unwrap_or(-1),
    })
}

fn slugify(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("default");
    }
    out
}

fn fullboot_label(config: &RunConfig) -> String {
    let mut label = slugify(&config.profile);
    if let Some(case) = &config.case_filter {
        label.push_str("__");
        label.push_str(&slugify(case));
    }
    label
}

fn kernel_cmdline(config: &RunConfig) -> String {
    let mut parts = vec![
        format!("run_integration={}", config.profile),
        String::from("shell=off"),
    ];
    if config.profile != "boot-smoke" && cpu_hotplug_mode(&config.profile).is_none() {
        parts.push(String::from("qemu_no_if=1"));
    }
    if config.profile == "step9-heavy" {
        parts.push(String::from("kgdb=on"));
        parts.push(String::from("kgdb_transport=both"));
        parts.push(String::from("kgdb_serial_exclusive=1"));
    }
    if let Some(case) = &config.case_filter {
        parts.push(format!("run_case={case}"));
    }
    parts.join(" ")
}

fn profile_needs_storage_disk(profile: &str) -> bool {
    matches!(
        profile,
        "storage" | "pr-required" | "nightly-required" | "step9-heavy"
    )
}

fn profile_needs_boot_artifacts(profile: &str) -> bool {
    matches!(
        profile,
        "storage" | "driver_domain" | "iommu" | "pr-required" | "nightly-required"
    )
}

fn profile_needs_driver_domain_cells(profile: &str) -> bool {
    matches!(
        profile,
        "driver_domain" | "pr-required" | "nightly-required"
    )
}

fn copy_cells_dir(src_dir: &Path, dst_dir: &Path) -> Result<usize, BuildError> {
    if !src_dir.exists() {
        return Ok(0);
    }
    std::fs::create_dir_all(dst_dir).map_err(|source| BuildError::Io {
        step: "create fullboot cells directory",
        source,
    })?;
    let mut copied = 0usize;
    for entry in std::fs::read_dir(src_dir).map_err(|source| BuildError::Io {
        step: "read source cells directory",
        source,
    })? {
        let entry = entry.map_err(|source| BuildError::Io {
            step: "read source cells directory entry",
            source,
        })?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        std::fs::copy(&path, dst_dir.join(file_name)).map_err(|source| BuildError::Io {
            step: "copy cell asset into fullboot image",
            source,
        })?;
        copied += 1;
    }
    Ok(copied)
}

fn ensure_runtime_boot_artifact_assets(root: &Path) -> Result<(), BuildError> {
    let boot_artifacts_dir = root
        .join("target")
        .join("x86_64-exorust")
        .join("release")
        .join("boot_artifacts");
    let drivers_dir = boot_artifacts_dir.join("drivers");
    let cells_dir = boot_artifacts_dir.join("cells");
    let cell_v1 = cells_dir.join("driver_cell_probe_v1.cell");
    let cell_v2 = cells_dir.join("driver_cell_probe_v2.cell");
    let driver_probe = drivers_dir.join("driver_cell_probe.cell");
    let driver_probe_pci = drivers_dir.join("driver_cell_probe_pci.cell");
    let have_assets =
        driver_probe.exists() && driver_probe_pci.exists() && cell_v1.exists() && cell_v2.exists();
    if have_assets {
        return Ok(());
    }

    run_command(
        root,
        "build runtime boot artifact assets",
        "bash",
        &[
            "scripts/build_runtime_boot_artifacts.sh",
            "--profile",
            "release",
        ],
    )?;

    if driver_probe.exists() && driver_probe_pci.exists() && cell_v1.exists() && cell_v2.exists() {
        Ok(())
    } else {
        Err(BuildError::ArtifactMissing {
            step: "build runtime boot artifact assets",
            path: boot_artifacts_dir,
        })
    }
}

fn build_storage_test_disk(boot_root: &Path) -> Result<PathBuf, BuildError> {
    let disk_path = boot_root.join("storage.img");

    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| BuildError::Io {
            step: "create storage test disk directory",
            source,
        })?;
    }

    let byte_len = (STORAGE_TEST_DISK_TOTAL_SECTORS as usize)
        .checked_mul(STORAGE_TEST_DISK_SECTOR_SIZE)
        .ok_or_else(|| BuildError::Io {
            step: "size storage test disk",
            source: std::io::Error::other("storage test disk size overflow"),
        })?;
    let mut image = vec![0u8; byte_len];
    let bs = &mut image[..STORAGE_TEST_DISK_SECTOR_SIZE];

    // Minimal FAT32 BPB enough for mount smoke used by kernel integration test.
    bs[11..13].copy_from_slice(&(STORAGE_TEST_DISK_SECTOR_SIZE as u16).to_le_bytes());
    bs[13] = 1; // sectors/cluster
    bs[14..16].copy_from_slice(&32u16.to_le_bytes()); // reserved sectors
    bs[16] = 2; // FAT count
    bs[32..36].copy_from_slice(&STORAGE_TEST_DISK_TOTAL_SECTORS.to_le_bytes());
    bs[36..40].copy_from_slice(&1u32.to_le_bytes()); // sectors/FAT
    bs[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;

    std::fs::write(&disk_path, image).map_err(|source| BuildError::Io {
        step: "write storage test disk image",
        source,
    })?;
    Ok(disk_path)
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub fn build_exoloader_efi() -> Result<PathBuf, BuildError> {
    let root = workspace_root();
    run_cargo(
        &root,
        "build exoloader",
        &[
            "build",
            "-p",
            "exoloader",
            "--target",
            "x86_64-unknown-uefi",
            "-Z",
            "build-std=core,compiler_builtins,alloc",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
    )?;

    let path = root
        .join("target")
        .join("x86_64-unknown-uefi")
        .join("debug")
        .join("exoloader.efi");

    if path.exists() {
        Ok(path)
    } else {
        Err(BuildError::ArtifactMissing {
            step: "build exoloader",
            path,
        })
    }
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub fn build_kernel_elf() -> Result<PathBuf, BuildError> {
    let root = workspace_root();
    run_cargo(
        &root,
        "build kernel elf",
        &[
            "build",
            "-p",
            "rany_kernel",
            "--target",
            "x86_64-exorust.json",
            "--features",
            "qemu-test-export",
            "-Z",
            "json-target-spec",
            "-Z",
            "build-std=core,compiler_builtins,alloc",
            "-Z",
            "build-std-features=compiler-builtins-mem",
        ],
    )?;

    let path = root
        .join("target")
        .join("x86_64-exorust")
        .join("debug")
        .join("exorust_kernel");

    if path.exists() {
        Ok(path)
    } else {
        Err(BuildError::ArtifactMissing {
            step: "build kernel elf",
            path,
        })
    }
}

/// # Errors
///
/// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
pub fn build_signer() -> Result<PathBuf, BuildError> {
    let root = workspace_root();
    run_cargo(
        &root,
        "build kernel-signer",
        &[
            "build",
            "--manifest-path",
            "tools/signer/Cargo.toml",
            "--release",
        ],
    )?;

    let path = root
        .join("tools")
        .join("signer")
        .join("target")
        .join("release")
        .join(format!("kernel-signer{}", std::env::consts::EXE_SUFFIX));

    if path.exists() {
        Ok(path)
    } else {
        Err(BuildError::ArtifactMissing {
            step: "build kernel-signer",
            path,
        })
    }
}

/// # Errors
///
/// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
///
/// # Panics
///
/// Panics if a generated artifact or signing-key path is not valid Unicode.
pub fn package_fullboot_image(config: &RunConfig) -> Result<PackagedImage, BuildError> {
    let root = workspace_root();
    let exoloader_path = build_exoloader_efi()?;
    let kernel_elf_path = build_kernel_elf()?;
    let signer_path = build_signer()?;

    let label = fullboot_label(config);
    let boot_root = root
        .join("target")
        .join("qemu-boot")
        .join(format!("fullboot-{label}"));
    if boot_root.exists() {
        std::fs::remove_dir_all(&boot_root).map_err(|source| BuildError::Io {
            step: "remove old fullboot image",
            source,
        })?;
    }

    let efi_boot = boot_root.join("EFI").join("BOOT");
    std::fs::create_dir_all(&efi_boot).map_err(|source| BuildError::Io {
        step: "create fullboot EFI directory",
        source,
    })?;
    std::fs::copy(&exoloader_path, efi_boot.join("BOOTX64.EFI")).map_err(|source| {
        BuildError::Io {
            step: "copy exoloader.efi",
            source,
        }
    })?;

    let kernel_payload_path = boot_root.join("rany_os");
    let secret_key_path = root.join("keys").join("kernel.key");

    if !secret_key_path.exists() {
        return Err(BuildError::ArtifactMissing {
            step: "locate kernel signing key",
            path: secret_key_path,
        });
    }

    run_command(
        &root,
        "sign kernel",
        signer_path.to_str().unwrap(),
        &[
            "sign",
            "--kernel",
            kernel_elf_path.to_str().unwrap(),
            "--secret-key",
            secret_key_path.to_str().unwrap(),
            "--output",
            kernel_payload_path.to_str().unwrap(),
        ],
    )?;

    let kernel_out_dir = kernel_elf_path
        .parent()
        .ok_or_else(|| BuildError::ArtifactMissing {
            step: "locate kernel output directory",
            path: kernel_elf_path.clone(),
        })?;
    let kernel_fat_root = kernel_out_dir.join("fat_root");
    let needs_boot_artifacts = profile_needs_boot_artifacts(&config.profile);
    let needs_driver_domain_cells = profile_needs_driver_domain_cells(&config.profile);
    if needs_boot_artifacts {
        ensure_runtime_boot_artifact_assets(&root)?;
    }
    let boot_artifacts_src = {
        let primary = kernel_fat_root.join("boot_artifacts");
        let release_boot_artifacts = root
            .join("target")
            .join("x86_64-exorust")
            .join("release")
            .join("boot_artifacts");
        let debug_boot_artifacts = kernel_out_dir.join("boot_artifacts");
        if primary.exists() {
            primary
        } else if release_boot_artifacts.exists() {
            release_boot_artifacts
        } else {
            debug_boot_artifacts
        }
    };
    let drivers_src = boot_artifacts_src.join("drivers");
    let copied_drivers = if needs_boot_artifacts {
        copy_cells_dir(&drivers_src, &boot_root.join("drivers"))?
    } else {
        0
    };
    if needs_boot_artifacts && copied_drivers == 0 {
        return Err(BuildError::ArtifactMissing {
            step: "copy driver artifacts into fullboot image",
            path: drivers_src,
        });
    }

    let cells_src = boot_artifacts_src.join("cells");
    let copied_cells = if needs_driver_domain_cells {
        copy_cells_dir(&cells_src, &boot_root.join("cells"))?
    } else {
        0
    };
    if needs_driver_domain_cells && copied_cells == 0 {
        return Err(BuildError::ArtifactMissing {
            step: "copy driver_domain assets into fullboot image",
            path: cells_src,
        });
    }

    let config_text = String::from("timeout=0\ndefault=0\n\n[FullBoot]\nkernel=rany_os\n");
    std::fs::write(boot_root.join("exoloader.cfg"), config_text).map_err(|source| {
        BuildError::Io {
            step: "write exoloader.cfg",
            source,
        }
    })?;

    std::fs::write(
        boot_root.join("exoloader.cmdline"),
        format!("{}\n", kernel_cmdline(config)),
    )
    .map_err(|source| BuildError::Io {
        step: "write exoloader.cmdline",
        source,
    })?;

    Ok(PackagedImage {
        boot_root,
        kernel_payload_path,
    })
}

fn ensure_qemu_available() -> Result<(), RunError> {
    let probe = Command::new("qemu-system-x86_64")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match probe {
        Ok(_) => Ok(()),
        Err(_) => Err(RunError::QemuNotFound(String::from(
            "qemu-system-x86_64 was not found in PATH. Install QEMU first (for Ubuntu: sudo apt-get install qemu-system-x86).",
        )
        .into_boxed_str())),
    }
}

fn qemu_supports_accel(accel: &str) -> bool {
    let output = match Command::new("qemu-system-x86_64")
        .arg("-accel")
        .arg("help")
        .output()
    {
        Ok(output) => output,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    stdout.lines().chain(stderr.lines()).any(|line| {
        line.split_whitespace()
            .any(|token| token.eq_ignore_ascii_case(accel))
    })
}

fn kvm_is_available() -> bool {
    qemu_supports_accel("kvm")
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok()
}

fn select_fullboot_accel(
    preference: AccelPreference,
    kvm_available: bool,
) -> Result<FullbootAccel, RunError> {
    match preference {
        AccelPreference::Auto | AccelPreference::Kvm => {
            if kvm_available {
                Ok(FullbootAccel::Kvm)
            } else {
                let mode = match preference {
                    AccelPreference::Auto => "default",
                    AccelPreference::Kvm => "QEMU_TEST_ACCEL=kvm",
                    AccelPreference::Tcg => unreachable!(),
                };
                Err(RunError::AccelUnavailable(
                    format!(
                        "KVM acceleration is unavailable for full-boot tests ({mode}). \
Set QEMU_TEST_ACCEL=tcg to enable the slower software-emulated path explicitly."
                    )
                    .into_boxed_str(),
                ))
            }
        }
        AccelPreference::Tcg => Ok(FullbootAccel::Tcg),
    }
}

fn resolve_fullboot_accel() -> Result<FullbootAccel, RunError> {
    let preference = AccelPreference::parse(std::env::var("QEMU_TEST_ACCEL").ok().as_deref())?;
    select_fullboot_accel(preference, kvm_is_available())
}

fn ensure_ovmf_assets(root: &Path) -> Result<(PathBuf, PathBuf), RunError> {
    let ovmf_dir = root.join("assets").join("firmware").join("ovmf-x64");
    let code = ovmf_dir.join("OVMF_CODE.fd");
    let vars = ovmf_dir.join("OVMF_VARS.fd");
    if !code.exists() || !vars.exists() {
        return Err(RunError::FirmwareMissing(
            format!(
                "OVMF firmware is missing. Expected '{}' and '{}'.",
                code.display(),
                vars.display()
            )
            .into_boxed_str(),
        ));
    }
    Ok((code, vars))
}

fn detect_fullboot_result(log_path: &Path) -> Option<bool> {
    let bytes = std::fs::read(log_path).ok()?;
    let serial = String::from_utf8_lossy(&bytes);
    if serial.contains("[kernel-test] result pass") {
        return Some(true);
    }
    if serial.contains("[kernel-test] result fail") {
        return Some(false);
    }
    None
}

fn serial_contains(log_path: &Path, marker: &str) -> bool {
    std::fs::read(log_path)
        .ok()
        .is_some_and(|bytes| String::from_utf8_lossy(&bytes).contains(marker))
}

const CPU_HOTPLUG_READY: &str = "[kernel-test] cpu-hotplug ready";
const CPU_HOTPLUG_EJECT_READY: &str = "[kernel-test] cpu-hotplug eject-ready";
const CPU_HOTPLUG_SPARSE_ADD_READY: &str = "[kernel-test] cpu-hotplug sparse-add-ready";
const CPU_HOTPLUG_BLOCKER_EJECT_READY: &str = "[kernel-test] cpu-hotplug blocker-eject-ready";
const CPU_HOTPLUG_RETRY_EJECT_READY: &str = "[kernel-test] cpu-hotplug retry-eject-ready";
const CPU_HOTPLUG_READD_READY: &str = "[kernel-test] cpu-hotplug readd-ready";
const CPU_HOTPLUG_FINAL_EJECT_READY: &str = "[kernel-test] cpu-hotplug final-eject-ready";
const QMP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const QMP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CpuHotplugRunPhase {
    LifecycleAwaitingAdd,
    LifecycleAwaitingDelete,
    SparseAwaitingAdd,
    SparseAwaitingBlockedDelete,
    SparseAwaitingRetryDelete,
    SparseAwaitingReadd,
    SparseAwaitingFinalDelete,
    Complete,
}

struct CpuHotplugRun {
    client: QmpClient,
    phase: CpuHotplugRunPhase,
    added_cpu: Option<HotpluggedCpu>,
}

impl CpuHotplugRun {
    const fn new(client: QmpClient, mode: CpuHotplugMode) -> Self {
        Self {
            client,
            phase: match mode {
                CpuHotplugMode::Lifecycle => CpuHotplugRunPhase::LifecycleAwaitingAdd,
                CpuHotplugMode::Sparse => CpuHotplugRunPhase::SparseAwaitingAdd,
            },
            added_cpu: None,
        }
    }

    fn advance(&mut self, log_path: &Path, run_deadline: Instant) -> Result<(), QmpError> {
        match self.phase {
            CpuHotplugRunPhase::LifecycleAwaitingAdd
                if serial_contains(log_path, CPU_HOTPLUG_READY) =>
            {
                let deadline = qmp_operation_deadline(run_deadline);
                let cpu = self
                    .client
                    .add_available_cpu("rany-cpu-hotplug-1", 0, deadline)?;
                eprintln!("QMP added CPU device '{}'", cpu.device_id);
                self.added_cpu = Some(cpu);
                self.phase = CpuHotplugRunPhase::LifecycleAwaitingDelete;
            }
            CpuHotplugRunPhase::LifecycleAwaitingDelete
                if serial_contains(log_path, CPU_HOTPLUG_EJECT_READY) =>
            {
                let cpu = self.added_cpu()?.clone();
                let deadline = qmp_operation_deadline(run_deadline);
                self.client.request_cpu_delete(&cpu, deadline)?;
                expect_cpu_deleted(
                    self.client.wait_for_device_delete_outcome(&cpu, deadline)?,
                    "CPU hotplug lifecycle delete",
                )?;
                eprintln!("QMP observed DEVICE_DELETED for '{}'", cpu.device_id);
                self.phase = CpuHotplugRunPhase::Complete;
            }
            CpuHotplugRunPhase::SparseAwaitingAdd
                if serial_contains(log_path, CPU_HOTPLUG_SPARSE_ADD_READY) =>
            {
                let deadline = qmp_operation_deadline(run_deadline);
                let cpu =
                    self.client
                        .add_available_cpu("rany-cpu-hotplug-sparse-1", 1, deadline)?;
                eprintln!("QMP added sparse CPU device '{}'", cpu.device_id);
                self.added_cpu = Some(cpu);
                self.phase = CpuHotplugRunPhase::SparseAwaitingBlockedDelete;
            }
            CpuHotplugRunPhase::SparseAwaitingBlockedDelete
                if serial_contains(log_path, CPU_HOTPLUG_BLOCKER_EJECT_READY) =>
            {
                let cpu = self.added_cpu()?.clone();
                let deadline = qmp_operation_deadline(run_deadline);
                self.client.request_cpu_delete(&cpu, deadline)?;
                expect_cpu_delete_rejected(
                    self.client.wait_for_device_delete_outcome(&cpu, deadline)?,
                )?;
                eprintln!("QMP observed guest rejection for '{}'", cpu.device_id);
                self.phase = CpuHotplugRunPhase::SparseAwaitingRetryDelete;
            }
            CpuHotplugRunPhase::SparseAwaitingRetryDelete
                if serial_contains(log_path, CPU_HOTPLUG_RETRY_EJECT_READY) =>
            {
                let cpu = self.added_cpu()?.clone();
                let deadline = qmp_operation_deadline(run_deadline);
                self.client.request_cpu_delete(&cpu, deadline)?;
                expect_cpu_deleted(
                    self.client.wait_for_device_delete_outcome(&cpu, deadline)?,
                    "sparse CPU retry delete",
                )?;
                eprintln!("QMP deleted sparse CPU device '{}'", cpu.device_id);
                self.phase = CpuHotplugRunPhase::SparseAwaitingReadd;
            }
            CpuHotplugRunPhase::SparseAwaitingReadd
                if serial_contains(log_path, CPU_HOTPLUG_READD_READY) =>
            {
                let prior = self.added_cpu()?.clone();
                let deadline = qmp_operation_deadline(run_deadline);
                let cpu = self
                    .client
                    .readd_cpu(&prior, "rany-cpu-hotplug-sparse-2", deadline)?;
                eprintln!("QMP re-added sparse CPU device '{}'", cpu.device_id);
                self.added_cpu = Some(cpu);
                self.phase = CpuHotplugRunPhase::SparseAwaitingFinalDelete;
            }
            CpuHotplugRunPhase::SparseAwaitingFinalDelete
                if serial_contains(log_path, CPU_HOTPLUG_FINAL_EJECT_READY) =>
            {
                let cpu = self.added_cpu()?.clone();
                let deadline = qmp_operation_deadline(run_deadline);
                self.client.request_cpu_delete(&cpu, deadline)?;
                expect_cpu_deleted(
                    self.client.wait_for_device_delete_outcome(&cpu, deadline)?,
                    "sparse CPU final delete",
                )?;
                eprintln!("QMP deleted re-added CPU device '{}'", cpu.device_id);
                self.phase = CpuHotplugRunPhase::Complete;
            }
            _ => {}
        }
        Ok(())
    }

    fn added_cpu(&self) -> Result<&HotpluggedCpu, QmpError> {
        self.added_cpu.as_ref().ok_or_else(|| QmpError::Protocol {
            operation: "CPU hotplug run",
            detail: String::from("CPU hotplug phase has no device identity").into_boxed_str(),
        })
    }

    const fn is_complete(&self) -> bool {
        matches!(self.phase, CpuHotplugRunPhase::Complete)
    }
}

fn expect_cpu_deleted(
    outcome: DeviceDeleteOutcome,
    operation: &'static str,
) -> Result<(), QmpError> {
    match outcome {
        DeviceDeleteOutcome::Deleted => Ok(()),
        DeviceDeleteOutcome::GuestRejected {
            device,
            path,
            acpi_status,
        } => Err(QmpError::Protocol {
            operation,
            detail: format!(
                "guest rejected removal for device {:?}, path {:?}, ACPI status {:?}",
                device.as_deref(),
                path.as_deref(),
                acpi_status
            )
            .into_boxed_str(),
        }),
    }
}

fn expect_cpu_delete_rejected(outcome: DeviceDeleteOutcome) -> Result<(), QmpError> {
    match outcome {
        DeviceDeleteOutcome::GuestRejected { .. } => Ok(()),
        DeviceDeleteOutcome::Deleted => Err(QmpError::Protocol {
            operation: "blocked CPU hotplug delete",
            detail: String::from("guest removed a CPU that still had a pinned task blocker")
                .into_boxed_str(),
        }),
    }
}

fn qmp_operation_deadline(run_deadline: Instant) -> Instant {
    let operation_deadline = Instant::now() + QMP_OPERATION_TIMEOUT;
    operation_deadline.min(run_deadline)
}

fn reserve_qmp_address() -> Result<SocketAddr, RunError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(RunError::QemuLaunch)?;
    let address = listener.local_addr().map_err(RunError::QemuLaunch)?;
    drop(listener);
    Ok(address)
}

fn validate_cpu_topology(config: &RunConfig) -> Result<(), RunError> {
    if config.smp == 0 || config.smp > config.max_cpus || config.max_cpus > 256 {
        return Err(RunError::InvalidCpuTopology {
            initial_cpus: config.smp,
            max_cpus: config.max_cpus,
        });
    }
    Ok(())
}

fn make_report(
    profile: String,
    artifact_path: PathBuf,
    log_path: PathBuf,
    qemu_stderr_path: PathBuf,
    host_exit_code: i32,
    duration: Duration,
) -> RunReport {
    RunReport {
        profile,
        artifact_path,
        log_path,
        qemu_stderr_path,
        host_exit_code,
        isa_debug_value: normalize_qemu_exit_code(host_exit_code),
        duration,
    }
}

fn poll_qemu(
    config: &RunConfig,
    artifact_path: PathBuf,
    log_path: PathBuf,
    qemu_stderr_path: PathBuf,
    mut child: std::process::Child,
    qmp_client: Option<QmpClient>,
) -> Result<RunReport, RunError> {
    let start = Instant::now();
    let timeout = Duration::from_secs(config.timeout_secs);
    let run_deadline = start + timeout;
    let hotplug_mode = cpu_hotplug_mode(&config.profile);
    let mut hotplug = qmp_client.map(|client| {
        CpuHotplugRun::new(
            client,
            hotplug_mode.expect("QMP client requires a CPU hotplug profile"),
        )
    });

    loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Timeout {
                timeout_secs: config.timeout_secs,
                log_path: Box::new(log_path),
                qemu_stderr_path: Box::new(qemu_stderr_path),
            });
        }

        if let Some(hotplug) = hotplug.as_mut()
            && let Err(source) = hotplug.advance(&log_path, run_deadline)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Qmp {
                source: Box::new(source),
                log_path: Box::new(log_path),
                qemu_stderr_path: Box::new(qemu_stderr_path),
            });
        }

        if let Some(success) = detect_fullboot_result(&log_path) {
            if success && hotplug.as_ref().is_some_and(|run| !run.is_complete()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Qmp {
                    source: Box::new(QmpError::Protocol {
                        operation: "CPU hotplug run",
                        detail: String::from(
                            "guest reported success before DEVICE_DELETED was acknowledged",
                        )
                        .into_boxed_str(),
                    }),
                    log_path: Box::new(log_path),
                    qemu_stderr_path: Box::new(qemu_stderr_path),
                });
            }
            let _ = child.kill();
            let _ = child.wait();
            let host_exit_code = if success { 33 } else { 35 };
            let report = make_report(
                config.profile.clone(),
                artifact_path,
                log_path,
                qemu_stderr_path,
                host_exit_code,
                start.elapsed(),
            );
            if success {
                return Ok(report);
            }
            return Err(RunError::ProfileFailed(Box::new(report)));
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let host_exit_code = status.code().unwrap_or(-1);
                let token_result = detect_fullboot_result(&log_path);
                let report = make_report(
                    config.profile.clone(),
                    artifact_path,
                    log_path,
                    qemu_stderr_path,
                    host_exit_code,
                    start.elapsed(),
                );
                if token_result == Some(true) || report.isa_debug_value == Some(0x10) {
                    return Ok(report);
                }
                return Err(RunError::ProfileFailed(Box::new(report)));
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::QemuLaunch(err));
            }
        }
    }
}

/// # Errors
///
/// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
pub fn run_fullboot(config: &RunConfig) -> Result<RunReport, RunError> {
    validate_cpu_topology(config)?;
    ensure_qemu_available()?;
    let accel = resolve_fullboot_accel()?;
    let image = package_fullboot_image(config).map_err(|err| RunError::Build(Box::new(err)))?;

    let root = workspace_root();
    let (ovmf_code, ovmf_vars_template) = ensure_ovmf_assets(&root)?;

    let label = fullboot_label(config);
    let log_dir = root.join("target").join("qemu-logs");
    std::fs::create_dir_all(&log_dir).map_err(RunError::QemuLaunch)?;
    let log_path = log_dir.join(format!("fullboot-{label}.log"));
    std::fs::File::create(&log_path).map_err(RunError::QemuLaunch)?;
    let qemu_stderr_path = log_dir.join(format!("fullboot-{label}-qemu-stderr.log"));
    let qemu_stderr_file =
        std::fs::File::create(&qemu_stderr_path).map_err(RunError::QemuLaunch)?;

    let vars_copy_path = root
        .join("target")
        .join("qemu-boot")
        .join(format!("fullboot-{label}-OVMF_VARS.fd"));
    std::fs::copy(&ovmf_vars_template, &vars_copy_path).map_err(RunError::QemuLaunch)?;

    let serial_arg = format!("file:{}", log_path.display());
    let ovmf_code_arg = format!(
        "if=pflash,format=raw,readonly=on,file={}",
        ovmf_code.display()
    );
    let ovmf_vars_arg = format!("if=pflash,format=raw,file={}", vars_copy_path.display());
    let fat_arg = format!("format=raw,file=fat:rw:{}", image.boot_root.display());
    let storage_disk_path = if profile_needs_storage_disk(&config.profile) {
        Some(
            build_storage_test_disk(&image.boot_root)
                .map_err(|err| RunError::Build(Box::new(err)))?,
        )
    } else {
        None
    };
    let qmp_address = if cpu_hotplug_mode(&config.profile).is_some() {
        Some(reserve_qmp_address()?)
    } else {
        None
    };

    let mut qemu_cmd = Command::new("qemu-system-x86_64");
    eprintln!(
        "full-boot profile '{}' using QEMU accel '{}'",
        config.profile,
        accel.as_str()
    );
    qemu_cmd
        .arg("-machine")
        .arg(machine_arg_for_accel(accel))
        .arg("-accel")
        .arg(accel.as_str())
        .arg("-cpu")
        .arg(&config.cpu)
        .arg("-m")
        .arg(format!("{}M", config.memory_mb))
        .arg("-smp")
        .arg(format!("cpus={},maxcpus={}", config.smp, config.max_cpus))
        .arg("-nic")
        .arg("none")
        .arg("-display")
        .arg("none")
        .arg("-serial")
        .arg(serial_arg)
        .arg("-device")
        .arg("isa-debug-exit,iobase=0xf4,iosize=0x04")
        .arg("-no-reboot")
        .arg("-no-shutdown")
        .arg("-drive")
        .arg(ovmf_code_arg)
        .arg("-drive")
        .arg(ovmf_vars_arg)
        .arg("-drive")
        .arg(fat_arg)
        .stdout(Stdio::null())
        .stderr(Stdio::from(qemu_stderr_file));

    if let Some(address) = qmp_address {
        qemu_cmd
            .arg("-qmp")
            .arg(format!("tcp:{address},server=on,wait=off"));
    }

    if let Some(storage_disk) = &storage_disk_path {
        qemu_cmd
            .arg("-drive")
            .arg(format!(
                "file={},if=none,id=storage0,format=raw",
                storage_disk.display()
            ))
            .arg("-device")
            .arg("virtio-blk-pci,drive=storage0");
    }

    if config.profile == "driver_domain" {
        qemu_cmd
            .arg("-device")
            .arg("intel-hda")
            .arg("-device")
            .arg("hda-duplex");
    }

    qemu_cmd
        .arg("-device")
        .arg(iommu_device_arg(&config.profile));

    for extra in &config.extra_args {
        qemu_cmd.arg(extra);
    }

    let mut child = qemu_cmd.spawn().map_err(RunError::QemuLaunch)?;
    let qmp_client = match qmp_address {
        Some(address) => match QmpClient::connect(address, Instant::now() + QMP_CONNECT_TIMEOUT) {
            Ok(client) => Some(client),
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(RunError::Qmp {
                    source: Box::new(source),
                    log_path: Box::new(log_path),
                    qemu_stderr_path: Box::new(qemu_stderr_path),
                });
            }
        },
        None => None,
    };
    poll_qemu(
        config,
        image.kernel_payload_path,
        log_path,
        qemu_stderr_path,
        child,
        qmp_client,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_smoke_cmdline_keeps_interrupts_enabled() {
        let cfg = RunConfig::for_profile("boot-smoke");
        let cmdline = kernel_cmdline(&cfg);

        assert!(cmdline.contains("run_integration=boot-smoke"));
        assert!(cmdline.contains("shell=off"));
        assert!(!cmdline.contains("qemu_no_if=1"));
    }

    #[test]
    fn driver_domain_cmdline_keeps_qemu_no_if() {
        let cfg = RunConfig::for_profile("driver_domain");
        let cmdline = kernel_cmdline(&cfg);

        assert!(cmdline.contains("run_integration=driver_domain"));
        assert!(cmdline.contains("qemu_no_if=1"));
    }

    #[test]
    fn cpu_hotplug_cmdline_keeps_sci_delivery_enabled() {
        let cfg = RunConfig::for_profile("cpu-hotplug");
        let cmdline = kernel_cmdline(&cfg);

        assert!(cmdline.contains("run_integration=cpu-hotplug"));
        assert!(!cmdline.contains("qemu_no_if=1"));
        assert_eq!(cfg.smp, 1);
        assert_eq!(cfg.max_cpus, 2);
    }

    #[test]
    fn sparse_cpu_hotplug_profile_enumerates_all_possible_slots_with_eime() {
        let cfg = RunConfig::for_profile("cpu-hotplug-sparse");
        let cmdline = kernel_cmdline(&cfg);

        assert!(cmdline.contains("run_integration=cpu-hotplug-sparse"));
        assert!(!cmdline.contains("qemu_no_if=1"));
        assert_eq!(cfg.smp, 1);
        assert_eq!(cfg.max_cpus, 256);
        assert!(cfg.cpu.contains("+x2apic"));
        assert!(iommu_device_arg(&cfg.profile).contains("eim=on"));
    }

    #[test]
    fn lifecycle_cpu_hotplug_profile_keeps_xapic_compatible_remapping() {
        let cfg = RunConfig::for_profile("cpu-hotplug");

        assert!(!iommu_device_arg(&cfg.profile).contains("eim=on"));
    }

    #[test]
    fn network_profile_uses_kernel_fake_ports_without_driver_artifacts() {
        assert!(!profile_needs_boot_artifacts("network"));
        assert!(profile_needs_boot_artifacts("driver_domain"));
        assert!(profile_needs_boot_artifacts("pr-required"));
    }

    #[test]
    fn accel_preference_defaults_to_auto() {
        assert_eq!(AccelPreference::parse(None).unwrap(), AccelPreference::Auto);
        assert_eq!(
            AccelPreference::parse(Some("auto")).unwrap(),
            AccelPreference::Auto
        );
    }

    #[test]
    fn accel_preference_accepts_kvm_and_tcg() {
        assert_eq!(
            AccelPreference::parse(Some("kvm")).unwrap(),
            AccelPreference::Kvm
        );
        assert_eq!(
            AccelPreference::parse(Some("TCG")).unwrap(),
            AccelPreference::Tcg
        );
    }

    #[test]
    fn accel_preference_rejects_unknown_value() {
        let err = AccelPreference::parse(Some("hvf")).unwrap_err();
        assert!(matches!(err, RunError::InvalidAccel(_)));
    }

    #[test]
    fn auto_prefers_kvm_when_available() {
        assert_eq!(
            select_fullboot_accel(AccelPreference::Auto, true).unwrap(),
            FullbootAccel::Kvm
        );
    }

    #[test]
    fn auto_requires_explicit_tcg_when_kvm_is_missing() {
        let err = select_fullboot_accel(AccelPreference::Auto, false).unwrap_err();
        assert!(matches!(err, RunError::AccelUnavailable(_)));
    }

    #[test]
    fn explicit_tcg_is_allowed_without_kvm() {
        assert_eq!(
            select_fullboot_accel(AccelPreference::Tcg, false).unwrap(),
            FullbootAccel::Tcg
        );
    }

    #[test]
    fn kvm_machine_uses_split_irqchip() {
        assert_eq!(
            machine_arg_for_accel(FullbootAccel::Kvm),
            "q35,kernel-irqchip=split"
        );
        assert_eq!(machine_arg_for_accel(FullbootAccel::Tcg), "q35");
    }
}
