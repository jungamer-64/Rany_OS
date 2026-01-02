// This module delegates IVRS parsing to the ACPI driver crate to centralize parsing logic.
// Avoid duplicate implementations here; use `acpi_driver::ivrs` as the canonical implementation.

pub use acpi_driver::ivrs::*;
