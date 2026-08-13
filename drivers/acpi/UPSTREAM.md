# Provenance and licensing

This workspace-owned ACPI runtime was designed from the public API and object
ownership model of `acpi` 6.1.1, published by the rust-osdev project:

- crate: https://crates.io/crates/acpi/6.1.1
- source: https://github.com/rust-osdev/acpi
- upstream license: MIT OR Apache-2.0

No upstream source files are embedded verbatim. RanyOS implements its table
catalog, resumable AML VM, namespace, OperationRegion boundary, and GPE/Notify
dispatch locally under the workspace license. The upstream crate archive used
for provenance verification contains `LICENCE-MIT` and `LICENCE-APACHE`.
