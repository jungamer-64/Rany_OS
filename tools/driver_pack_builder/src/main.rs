use std::env;
use std::fs;
use std::path::PathBuf;

const DRIVER_PACK_MAGIC: [u8; 8] = *b"EXDRV\0\0\0";
const DRIVER_PACK_VERSION: u32 = 1;
const DRIVER_MANIFEST_VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverPackHeader {
    magic: [u8; 8],
    version: u32,
    header_size: u32,
    manifest_offset: u32,
    manifest_size: u32,
    elf_offset: u32,
    elf_size: u32,
    signature_offset: u32,
    signature_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DriverManifestV1 {
    abi_version: u32,
    abi_size: u32,
    flags: u32,
    name_len: u16,
    reserved0: u16,
    name: [u8; 32],
    driver_version: u64,
    driver_abi_version: u32,
    kernel_api_min_version: u32,
    required_caps: u64,
    pci_vendor_id: u16,
    pci_device_id: u16,
    pci_class: u8,
    pci_subclass: u8,
    pci_prog_if: u8,
    reserved1: u8,
    reserved2: [u64; 4],
}

#[derive(Default)]
struct Config {
    name: String,
    input: PathBuf,
    output: PathBuf,
    driver_abi_version: u32,
    kernel_api_min_version: u32,
    pci_vendor_id: u16,
    pci_device_id: u16,
    pci_class: u8,
    pci_subclass: u8,
    pci_prog_if: u8,
}

fn usage() -> ! {
    eprintln!(
        "usage: driver_pack_builder --name NAME --input PATH --output PATH \\
    [--driver-abi-version N] [--kernel-api-min-version N] \\
    [--pci-vendor-id N --pci-device-id N] \\
    [--pci-class N --pci-subclass N --pci-prog-if N]"
    );
    std::process::exit(2);
}

fn parse_numeric<T>(raw: &str) -> Result<T, String>
where
    T: TryFrom<u64>,
{
    let trimmed = raw.trim();
    let value = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|err| err.to_string())?
    } else {
        trimmed.parse::<u64>().map_err(|err| err.to_string())?
    };
    T::try_from(value).map_err(|_| format!("value out of range: {raw}"))
}

fn validate_pci_selector(
    vendor_id: u16,
    device_id: u16,
    class: u8,
    subclass: u8,
    prog_if: u8,
) -> Result<(), &'static str> {
    let has_vendor = vendor_id != 0;
    let has_device = device_id != 0;
    let has_class = class != 0;
    let has_subclass = subclass != 0;
    let has_prog_if = prog_if != 0;

    if !(has_vendor || has_device || has_class || has_subclass || has_prog_if) {
        return Ok(());
    }

    if has_vendor && has_device && !(has_class || has_subclass || has_prog_if) {
        return Ok(());
    }

    if has_device {
        return Err("use vendor+device only, or class+subclass+prog_if with optional vendor");
    }

    if has_class && has_subclass {
        return Ok(());
    }

    Err("use vendor+device only, or class+subclass+prog_if with optional vendor")
}

fn parse_args() -> Config {
    let mut cfg = Config {
        driver_abi_version: 2,
        kernel_api_min_version: 3,
        ..Config::default()
    };
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => cfg.name = args.next().unwrap_or_else(|| usage()),
            "--input" => cfg.input = PathBuf::from(args.next().unwrap_or_else(|| usage())),
            "--output" => cfg.output = PathBuf::from(args.next().unwrap_or_else(|| usage())),
            "--driver-abi-version" => {
                cfg.driver_abi_version = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --driver-abi-version: {err}");
                        usage()
                    });
            }
            "--kernel-api-min-version" => {
                cfg.kernel_api_min_version = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --kernel-api-min-version: {err}");
                        usage()
                    });
            }
            "--pci-vendor-id" => {
                cfg.pci_vendor_id = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --pci-vendor-id: {err}");
                        usage()
                    });
            }
            "--pci-device-id" => {
                cfg.pci_device_id = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --pci-device-id: {err}");
                        usage()
                    });
            }
            "--pci-class" => {
                cfg.pci_class = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --pci-class: {err}");
                        usage()
                    });
            }
            "--pci-subclass" => {
                cfg.pci_subclass = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --pci-subclass: {err}");
                        usage()
                    });
            }
            "--pci-prog-if" => {
                cfg.pci_prog_if = parse_numeric(&args.next().unwrap_or_else(|| usage()))
                    .unwrap_or_else(|err| {
                        eprintln!("invalid --pci-prog-if: {err}");
                        usage()
                    });
            }
            _ => {
                eprintln!("unknown argument: {arg}");
                usage();
            }
        }
    }

    if cfg.name.is_empty() || cfg.input.as_os_str().is_empty() || cfg.output.as_os_str().is_empty()
    {
        usage();
    }

    if let Err(err) = validate_pci_selector(
        cfg.pci_vendor_id,
        cfg.pci_device_id,
        cfg.pci_class,
        cfg.pci_subclass,
        cfg.pci_prog_if,
    ) {
        eprintln!("invalid PCI selector: {err}");
        std::process::exit(2);
    }

    cfg
}

fn append_repr_c<T>(buffer: &mut Vec<u8>, value: &T) {
    let bytes = unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    };
    buffer.extend_from_slice(bytes);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_args();
    let elf = fs::read(&cfg.input)?;

    let mut name_bytes = [0u8; 32];
    let raw_name = cfg.name.as_bytes();
    let name_len = raw_name.len().min(name_bytes.len());
    name_bytes[..name_len].copy_from_slice(&raw_name[..name_len]);

    let header_size = std::mem::size_of::<DriverPackHeader>() as u32;
    let manifest_size = std::mem::size_of::<DriverManifestV1>() as u32;
    let manifest_offset = header_size;
    let elf_offset = manifest_offset + manifest_size;

    let header = DriverPackHeader {
        magic: DRIVER_PACK_MAGIC,
        version: DRIVER_PACK_VERSION,
        header_size,
        manifest_offset,
        manifest_size,
        elf_offset,
        elf_size: elf.len() as u32,
        signature_offset: 0,
        signature_size: 0,
    };

    let manifest = DriverManifestV1 {
        abi_version: DRIVER_MANIFEST_VERSION,
        abi_size: manifest_size,
        flags: 0,
        name_len: name_len as u16,
        reserved0: 0,
        name: name_bytes,
        driver_version: 0,
        driver_abi_version: cfg.driver_abi_version,
        kernel_api_min_version: cfg.kernel_api_min_version,
        required_caps: 0,
        pci_vendor_id: cfg.pci_vendor_id,
        pci_device_id: cfg.pci_device_id,
        pci_class: cfg.pci_class,
        pci_subclass: cfg.pci_subclass,
        pci_prog_if: cfg.pci_prog_if,
        reserved1: 0,
        reserved2: [0; 4],
    };

    let mut pack = Vec::with_capacity(header_size as usize + manifest_size as usize + elf.len());
    append_repr_c(&mut pack, &header);
    append_repr_c(&mut pack, &manifest);
    pack.extend_from_slice(&elf);

    if let Some(parent) = cfg.output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&cfg.output, pack)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_pci_selector;

    #[test]
    fn accepts_exact_vendor_device_selector() {
        assert!(validate_pci_selector(0x15b3, 0x1017, 0, 0, 0).is_ok());
    }

    #[test]
    fn accepts_class_selector_with_zero_prog_if() {
        assert!(validate_pci_selector(0, 0, 0x04, 0x03, 0x00).is_ok());
        assert!(validate_pci_selector(0x8086, 0, 0x04, 0x03, 0x00).is_ok());
    }

    #[test]
    fn rejects_partial_selector_shapes() {
        assert!(validate_pci_selector(0x8086, 0, 0, 0, 0).is_err());
        assert!(validate_pci_selector(0, 0, 0x04, 0, 0).is_err());
        assert!(validate_pci_selector(0, 0x1234, 0x04, 0x03, 0x00).is_err());
    }
}
