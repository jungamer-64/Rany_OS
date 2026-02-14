use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub suite: String,
    pub timeout_secs: u64,
    pub memory_mb: u64,
    pub smp: u8,
    pub cpu: String,
    pub extra_args: Vec<String>,
}

impl RunConfig {
    #[must_use]
    pub fn for_suite(suite: impl Into<String>) -> Self {
        Self {
            suite: suite.into(),
            timeout_secs: 60,
            memory_mb: 512,
            smp: 1,
            cpu: String::from("qemu64,+rdtscp"),
            extra_args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub suite: String,
    pub package: String,
    pub binary_name: String,
    pub binary_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub suite: String,
    pub artifact_path: PathBuf,
    pub log_path: PathBuf,
    pub qemu_stderr_path: PathBuf,
    pub host_exit_code: i32,
    pub isa_debug_value: Option<u32>,
    pub duration: Duration,
}

#[derive(Debug)]
pub enum BuildError {
    UnknownSuite(String),
    CargoLaunch(std::io::Error),
    CargoFailed(i32),
    ArtifactMissing(PathBuf),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::UnknownSuite(suite) => write!(f, "unknown suite: {suite}"),
            BuildError::CargoLaunch(err) => write!(f, "failed to launch cargo: {err}"),
            BuildError::CargoFailed(code) => {
                write!(f, "cargo build failed with exit code {code}")
            }
            BuildError::ArtifactMissing(path) => {
                write!(f, "suite artifact not found: {}", path.display())
            }
        }
    }
}

impl std::error::Error for BuildError {}

#[derive(Debug)]
pub enum RunError {
    Build(BuildError),
    QemuNotFound(String),
    FirmwareMissing(String),
    QemuLaunch(std::io::Error),
    Timeout {
        timeout_secs: u64,
        log_path: PathBuf,
        qemu_stderr_path: PathBuf,
    },
    SuiteFailed(RunReport),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Build(err) => write!(f, "build failed: {err}"),
            RunError::QemuNotFound(msg) => write!(f, "{msg}"),
            RunError::FirmwareMissing(msg) => write!(f, "{msg}"),
            RunError::QemuLaunch(err) => write!(f, "failed to launch qemu-system-x86_64: {err}"),
            RunError::Timeout {
                timeout_secs,
                log_path,
                qemu_stderr_path,
            } => write!(
                f,
                "suite timed out after {timeout_secs}s (serial log: {}, qemu stderr log: {})",
                log_path.display(),
                qemu_stderr_path.display()
            ),
            RunError::SuiteFailed(report) => write!(
                f,
                "suite '{}' failed (host exit: {}, serial log: {}, qemu stderr log: {})",
                report.suite,
                report.host_exit_code,
                report.log_path.display(),
                report.qemu_stderr_path.display()
            ),
        }
    }
}

impl std::error::Error for RunError {}

#[must_use]
pub fn normalize_qemu_exit_code(host_exit_code: i32) -> Option<u32> {
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

fn suite_package_name(suite: &str) -> Option<&'static str> {
    match suite {
        "core" => Some("qemu_suite_core"),
        "drivers" => Some("qemu_suite_drivers"),
        "fs" => Some("qemu_suite_fs"),
        "kernel" => Some("qemu_suite_kernel"),
        "tools" => Some("qemu_suite_tools"),
        "graphics" => Some("qemu_suite_graphics"),
        "pending" => Some("qemu_suite_pending"),
        _ => None,
    }
}

pub fn build_suite(suite: &str) -> Result<Artifact, BuildError> {
    let package = suite_package_name(suite)
        .ok_or_else(|| BuildError::UnknownSuite(String::from(suite)))?
        .to_string();

    let root = workspace_root();

    let mut build_cmd = Command::new("cargo");
    build_cmd
        .current_dir(&root)
        .arg("build")
        .arg("-p")
        .arg(&package)
        .arg("--target")
        .arg("x86_64-unknown-uefi")
        .arg("-Z")
        .arg("build-std=core,compiler_builtins,alloc")
        .arg("-Z")
        .arg("build-std-features=compiler-builtins-mem");

    let status = build_cmd.status().map_err(BuildError::CargoLaunch)?;
    if !status.success() {
        return Err(BuildError::CargoFailed(status.code().unwrap_or(-1)));
    }

    let binary_path = root
        .join("target")
        .join("x86_64-unknown-uefi")
        .join("debug")
        .join(format!("{package}.efi"));
    if !binary_path.exists() {
        return Err(BuildError::ArtifactMissing(binary_path));
    }

    Ok(Artifact {
        suite: String::from(suite),
        package,
        binary_name: suite_package_name(suite).unwrap_or("unknown").to_string(),
        binary_path,
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
        ))),
    }
}

fn ensure_ovmf_assets(root: &Path) -> Result<(PathBuf, PathBuf), RunError> {
    let ovmf_dir = root.join("assets").join("firmware").join("ovmf-x64");
    let code = ovmf_dir.join("OVMF_CODE.fd");
    let vars = ovmf_dir.join("OVMF_VARS.fd");
    if !code.exists() || !vars.exists() {
        return Err(RunError::FirmwareMissing(format!(
            "OVMF firmware is missing. Expected '{}' and '{}'.",
            code.display(),
            vars.display()
        )));
    }
    Ok((code, vars))
}

fn detect_suite_result(log_path: &Path, suite: &str) -> Option<bool> {
    let bytes = std::fs::read(log_path).ok()?;
    let serial = String::from_utf8_lossy(&bytes);
    let pass = format!("[qemu-suite] {suite} pass");
    if serial.contains(&pass) {
        return Some(true);
    }
    let fail = format!("[qemu-suite] {suite} fail");
    if serial.contains(&fail) {
        return Some(false);
    }
    None
}

fn make_report(
    suite: String,
    artifact_path: PathBuf,
    log_path: PathBuf,
    qemu_stderr_path: PathBuf,
    host_exit_code: i32,
    duration: Duration,
) -> RunReport {
    RunReport {
        suite,
        artifact_path,
        log_path,
        qemu_stderr_path,
        host_exit_code,
        isa_debug_value: normalize_qemu_exit_code(host_exit_code),
        duration,
    }
}

/// Shared QEMU execution loop: poll serial log for pass/fail markers and
/// wait for QEMU to exit within the configured timeout.
fn poll_qemu(
    config: &RunConfig,
    artifact_path: PathBuf,
    log_path: PathBuf,
    qemu_stderr_path: PathBuf,
    mut child: std::process::Child,
) -> Result<RunReport, RunError> {
    let start = Instant::now();
    let timeout = Duration::from_secs(config.timeout_secs);

    loop {
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Timeout {
                timeout_secs: config.timeout_secs,
                log_path,
                qemu_stderr_path,
            });
        }

        if let Some(success) = detect_suite_result(&log_path, &config.suite) {
            let _ = child.kill();
            let _ = child.wait();
            let host_exit_code = if success { 33 } else { 35 };
            let report = make_report(
                config.suite.clone(),
                artifact_path.clone(),
                log_path.clone(),
                qemu_stderr_path.clone(),
                host_exit_code,
                start.elapsed(),
            );
            if success {
                return Ok(report);
            }
            return Err(RunError::SuiteFailed(report));
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let host_exit_code = status.code().unwrap_or(-1);
                let suite_token_result = detect_suite_result(&log_path, &config.suite);
                let report = make_report(
                    config.suite.clone(),
                    artifact_path.clone(),
                    log_path.clone(),
                    qemu_stderr_path.clone(),
                    host_exit_code,
                    start.elapsed(),
                );

                if suite_token_result == Some(true) || report.isa_debug_value == Some(0x10) {
                    return Ok(report);
                }
                return Err(RunError::SuiteFailed(report));
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

/// Run a UEFI suite binary via OVMF firmware.
pub fn run_suite(config: RunConfig) -> Result<RunReport, RunError> {
    ensure_qemu_available()?;
    let artifact = build_suite(&config.suite).map_err(RunError::Build)?;

    let root = workspace_root();
    let (ovmf_code, ovmf_vars_template) = ensure_ovmf_assets(&root)?;
    let log_dir = root.join("target").join("qemu-logs");
    std::fs::create_dir_all(&log_dir).map_err(RunError::QemuLaunch)?;
    let log_path = log_dir.join(format!("suite-{}.log", config.suite));
    std::fs::File::create(&log_path).map_err(RunError::QemuLaunch)?;
    let qemu_stderr_path = log_dir.join(format!("suite-{}-qemu-stderr.log", config.suite));
    let qemu_stderr_file =
        std::fs::File::create(&qemu_stderr_path).map_err(RunError::QemuLaunch)?;

    let boot_root = root
        .join("target")
        .join("qemu-boot")
        .join(format!("suite-{}", config.suite));
    if boot_root.exists() {
        std::fs::remove_dir_all(&boot_root).map_err(RunError::QemuLaunch)?;
    }
    let efi_boot = boot_root.join("EFI").join("BOOT");
    std::fs::create_dir_all(&efi_boot).map_err(RunError::QemuLaunch)?;
    std::fs::copy(&artifact.binary_path, efi_boot.join("BOOTX64.EFI"))
        .map_err(RunError::QemuLaunch)?;

    let vars_copy_path = root
        .join("target")
        .join("qemu-boot")
        .join(format!("suite-{}-OVMF_VARS.fd", config.suite));
    std::fs::copy(&ovmf_vars_template, &vars_copy_path).map_err(RunError::QemuLaunch)?;

    let serial_arg = format!("file:{}", log_path.display());
    let ovmf_code_arg = format!(
        "if=pflash,format=raw,readonly=on,file={}",
        ovmf_code.display()
    );
    let ovmf_vars_arg = format!("if=pflash,format=raw,file={}", vars_copy_path.display());
    let fat_arg = format!("format=raw,file=fat:rw:{}", boot_root.display());

    let mut qemu_cmd = Command::new("qemu-system-x86_64");
    qemu_cmd
        .arg("-machine")
        .arg("q35,accel=tcg")
        .arg("-cpu")
        .arg(&config.cpu)
        .arg("-m")
        .arg(format!("{}M", config.memory_mb))
        .arg("-smp")
        .arg(config.smp.to_string())
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

    for extra in &config.extra_args {
        qemu_cmd.arg(extra);
    }

    let child = qemu_cmd.spawn().map_err(RunError::QemuLaunch)?;
    poll_qemu(
        &config,
        artifact.binary_path.clone(),
        log_path,
        qemu_stderr_path,
        child,
    )
}
