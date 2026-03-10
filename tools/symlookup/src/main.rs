use anyhow::{Context, Result, bail};
use object::{Object, ObjectSymbol};
use std::path::PathBuf;

/// Parse a hex address string, with or without "0x"/"0X" prefix
fn parse_hex_address(s: &str) -> Result<usize> {
    if s.starts_with("0x") || s.starts_with("0X") {
        Ok(usize::from_str_radix(&s[2..], 16)?)
    } else {
        Ok(usize::from_str_radix(s, 16)?)
    }
}

/// Find the symbol whose address is closest to (and <=) the given address
fn find_nearest_symbol(obj: &object::File, addr: usize) -> Option<(usize, String)> {
    let mut best: Option<(usize, String)> = None;

    for symbol in obj.symbols() {
        if let Some(sym_addr) = symbol.address().checked_add(0) {
            if sym_addr <= addr as u64 {
                let name = symbol.name().unwrap_or("<unknown>").to_string();
                let dist = (addr as u64).saturating_sub(sym_addr) as usize;
                if best.is_none() || dist < best.as_ref().unwrap().0 {
                    best = Some((dist, name));
                }
            }
        }
    }

    best
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1); // nosemgrep: codacy.tools-configs.rust.lang.security.args.args
    let addr_str = args
        .next()
        .context("Usage: symlookup <hex-address> [path-to-binary]")?;
    let addr = parse_hex_address(&addr_str)?;

    let bin = args
        .next()
        .unwrap_or_else(|| "target/x86_64-exorust/debug/exorust_kernel".to_string());

    let data = std::fs::read(&bin).with_context(|| format!("failed to read {}", bin))?;
    let obj = object::File::parse(&*data)?;

    if let Some((dist, name)) = find_nearest_symbol(&obj, addr) {
        println!(
            "Closest symbol: {} + {:#x} (distance {:#x})",
            name, dist, dist
        );
    } else {
        bail!("No symbol found in binary")
    }

    Ok(())
}
