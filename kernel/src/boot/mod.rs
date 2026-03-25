pub(crate) use boot_proto::EXO_BOOT_INFO_VERSION;
use boot_proto::ExoBootInfo;

pub mod entry;
pub use entry::*;

#[path = "../kernel_main.rs"]
mod phases;
pub use phases::*;

pub fn enter(boot_info: &'static ExoBootInfo) -> ! {
    phases::kmain_inner(boot_info)
}
