use core::sync::atomic::{AtomicBool, Ordering};

/// Minimal PCID support shim for host test builds.
/// Provides a tiny feature detection/initialization shim used by `tlb_batch`.

pub const MAX_PCID: u16 = 256;

pub static PCID_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn has_pcid() -> bool {
    PCID_INITIALIZED.load(Ordering::Relaxed)
}

pub fn has_invpcid() -> bool {
    false
}

pub fn init_pcid_features() {
    PCID_INITIALIZED.store(true, Ordering::Relaxed);
}

pub fn enable_pcid() -> Result<(), ()> {
    PCID_INITIALIZED.store(true, Ordering::Relaxed);
    Ok(())
}