//! Diagnostic checkpoints for a single firmware boot attempt.

use core::fmt::{self, Write};
use uefi::runtime::{self, VariableAttributes, VariableVendor};
use uefi::{CStr16, Guid, Status, cstr16};

use crate::serial_println;

const CAPACITY: usize = 8192;
const CHECKPOINT_SPACE: usize = 256;

static VENDOR: VariableVendor =
    VariableVendor(Guid::parse_or_panic("b6f9e4a1-5678-1234-abcd-ef0123456789"));
const ATTRIBUTES: VariableAttributes = VariableAttributes::from_bits_truncate(
    VariableAttributes::NON_VOLATILE.bits()
        | VariableAttributes::BOOTSERVICE_ACCESS.bits()
        | VariableAttributes::RUNTIME_ACCESS.bits(),
);
const CURRENT: &CStr16 = cstr16!("ExoBootLog0");
const PREVIOUS: &CStr16 = cstr16!("ExoBootLog1");
const OLDEST: &CStr16 = cstr16!("ExoBootLog2");

pub(super) enum Checkpoint {
    Started,
    Returned(Status),
    ExitBootServicesPending,
    MemoryMapRejected,
    MemoryMapPublicationRejected,
    KernelHandoffReady,
}

/// Owns the bounded text of the current attempt. A checkpoint replaces the
/// previous status in the serialized variable and can be written after the
/// firmware allocator has been retired.
pub(super) struct BootLog {
    bytes: [u8; CAPACITY],
    len: usize,
}

impl BootLog {
    pub(super) fn start() -> Self {
        if let Err(status) = rotate() {
            serial_println!("[BootLog] Log rotation incomplete: {status:?}");
        }
        let mut log = Self {
            bytes: [0; CAPACITY],
            len: 0,
        };
        log.note(format_args!("=== ExoRust Boot Log ==="));
        log.publish(Checkpoint::Started);
        log
    }

    pub(super) fn note(&mut self, args: fmt::Arguments<'_>) {
        let mut writer = BufferWriter {
            bytes: &mut self.bytes[self.len..CAPACITY - CHECKPOINT_SPACE],
            len: 0,
        };
        if writeln!(writer, "{args}").is_ok() {
            self.len += writer.len;
        }
    }

    pub(super) fn publish(&mut self, checkpoint: Checkpoint) {
        let mut writer = BufferWriter {
            bytes: &mut self.bytes[self.len..],
            len: 0,
        };
        let result = match checkpoint {
            Checkpoint::Started => writeln!(writer, "Status: loader started"),
            Checkpoint::Returned(status) => writeln!(writer, "Status: loader returned {status:?}"),
            Checkpoint::ExitBootServicesPending => {
                writeln!(writer, "Status: ExitBootServices pending")
            }
            Checkpoint::MemoryMapRejected => writeln!(
                writer,
                "Status: final memory map rejected after ExitBootServices"
            ),
            Checkpoint::MemoryMapPublicationRejected => writeln!(
                writer,
                "Status: memory map publication rejected after ExitBootServices"
            ),
            Checkpoint::KernelHandoffReady => writeln!(writer, "Status: kernel handoff ready"),
        };
        if result.is_err() {
            serial_println!("[BootLog] Checkpoint exceeded its reserved space");
            return;
        }

        let end = self.len + writer.len;
        if let Err(error) = runtime::set_variable(CURRENT, &VENDOR, ATTRIBUTES, &self.bytes[..end])
        {
            serial_println!("[BootLog] Checkpoint not saved: {error:?}");
        }
    }
}

struct BufferWriter<'a> {
    bytes: &'a mut [u8],
    len: usize,
}

impl Write for BufferWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn rotate() -> Result<(), Status> {
    let mut scratch = [0u8; CAPACITY];
    for (source, destination) in [(PREVIOUS, OLDEST), (CURRENT, PREVIOUS)] {
        match runtime::get_variable(source, &VENDOR, &mut scratch) {
            Ok((data, _)) => {
                runtime::set_variable(destination, &VENDOR, ATTRIBUTES, data)
                    .map_err(|error| error.status())?;
            }
            Err(error) if error.status() == Status::NOT_FOUND => {}
            Err(error) => return Err(error.status()),
        }
    }
    Ok(())
}
