use anyhow::{bail, Context, Result};
use object::{Object, ObjectSymbol};
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1); // nosemgrep: codacy.tools-configs.rust.lang.security.args.args
    let addr_str = args
        .next()
        .context("Usage: symlookup <hex-address> [path-to-binary]")?;
    let addr = if addr_str.starts_with("0x") || addr_str.starts_with("0X") {
        usize::from_str_radix(&addr_str[2..], 16)?
    } else {
        usize::from_str_radix(&addr_str, 16)?
    };

    let bin = args
        .next()
        .unwrap_or_else(|| "target/x86_64-exorust/debug/exorust_kernel".to_string());

    let data = std::fs::read(&bin).with_context(|| format!("failed to read {}", bin))?;
    let obj = object::File::parse(&*data)?;

    // Find the best symbol whose address <= addr
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

    if let Some((dist, name)) = best {
        println!("Closest symbol: {} + {:#x} (distance {:#x})", name, dist, dist);
    } else {
        bail!("No symbol found in binary")
    }

    Ok(())
}