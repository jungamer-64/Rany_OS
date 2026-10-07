//! Fingerprints the foreign driver declarations from tracked ABI sources.
//! Required declarations must exist before an artifact identity is published.

const ABI_DECLARATIONS: &[&str] = &[
    "pub struct DriverContext",
    "pub struct DriverVTable",
    "pub struct DriverCapabilities",
    "pub struct AbiDmaAllocation",
    "pub enum AbiDmaOperation",
    "pub enum AbiDmaStatus",
    "pub struct AbiDmaRequest",
    "pub struct AbiDmaResponse",
    "pub struct AbiRxWritableRegion",
    "pub struct AbiRxLease",
    "pub struct AbiTxDeviceOutcome",
    "pub struct AbiNetRxFrameLayout",
    "pub struct AbiNetRxMeta",
    "pub struct AbiNetTxSegment",
    "pub struct AbiNetTxSubmission",
    "pub struct AbiNetPortRuntime",
    "pub struct AbiNetPortRegistration",
    "pub struct KernelApiV4",
    "pub struct AbiTaskWaker",
    "pub struct AbiTaskFuture",
    "pub struct AbiTaskOptions",
    "pub struct AbiTaskSpawnResult",
    "pub struct AbiTimerSchedule",
    "pub struct AbiTimerRegistration",
    "pub struct AbiTimerAdmission",
    "pub struct AbiTimeSnapshot",
    "pub struct AbiTimerStatistics",
    "pub struct DriverExportsV1",
    "pub enum AbiDriverType",
    "pub enum AbiError",
    "pub struct PackedPciLocation",
    "pub struct AbiNvmeNamespaceInfo",
    "pub struct AbiNvmeNamespaceRegistration",
    "pub enum AbiNetDriverEventKind",
    "pub struct AbiNetDriverEvent",
    "pub struct AbiNetPortStats",
    "pub struct AbiNetPortInfo",
    "pub struct AbiMmioGrant",
    "pub struct AbiInterfaceScope",
    "pub struct AbiRRefRaw",
    "pub struct AbiExportedState",
    "pub struct AbiBlockQueueInfo",
    "pub struct AbiBlockSubmission",
    "pub enum AbiBlockDisposition",
    "pub struct AbiBlockSubmitOutcome",
    "pub struct AbiBlockCompletion",
    "pub struct AbiBlockDeviceRegistration",
    "pub enum AbiBlockTransport",
    "pub enum AbiBlockCommandKind",
    "pub struct AbiBlockDeviceInfo",
    "pub struct AbiNetTxMeta",
    "pub struct AbiMsixVectorInfo",
    "pub struct AbiBalloonPage",
    "pub enum BalloonPageCommand",
    "pub enum BalloonPageError",
    "pub type ProviderDescriptorsFn",
    "pub type AbiRRefDropFn",
    "pub type DriverExportStateFn",
    "pub type DriverImportStateFn",
    "pub type DriverEntryFn",
    "pub type BalloonPageCommandFn",
];

pub(super) fn calculate_abi_hash(content: &str) -> u64 {
    let mut hasher = Fnv1aHasher::new();
    for line in repr_lines_for_decls(content, ABI_DECLARATIONS) {
        hasher.write(line.as_bytes());
    }
    for declaration in ABI_DECLARATIONS {
        extract_and_hash_decl(content, declaration, &mut hasher);
    }
    hasher.finish()
}

fn extract_and_hash_decl(content: &str, decl_start: &str, hasher: &mut Fnv1aHasher) {
    let start_idx = content
        .match_indices(decl_start)
        .find(|&(index, _)| {
            let prefix = content[..index].rsplit('\n').next().unwrap_or("");
            let suffix = &content[index + decl_start.len()..];
            prefix.trim().is_empty()
                && suffix
                    .chars()
                    .next()
                    .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
        })
        .map(|(index, _)| index)
        .unwrap_or_else(|| panic!("missing ABI declaration: {decl_start}"));
    {
        let rest = &content[start_idx..];
        let mut depth = 0;
        let mut check = false;

        let mut buffer = String::new();
        let mut terminated = false;

        for line in rest.lines() {
            // Strip comments
            let line_content = line.find("//").map_or(line, |idx| &line[..idx]);

            // Count braces in the effective content
            for c in line_content.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        check = true;
                    }
                    '}' => {
                        depth -= 1;
                    }
                    _ => {}
                }
            }

            // Normalize: remove all whitespace for the hash
            let normalized: String = line_content
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            buffer.push_str(&normalized);

            // A balanced body or a tuple/type declaration terminates here.
            if depth == 0 && (check || line_content.trim_end().ends_with(';')) {
                terminated = true;
                break;
            }
        }
        assert!(terminated, "unterminated ABI declaration: {decl_start}");
        hasher.write(buffer.as_bytes());
    }
}

fn repr_lines_for_decls(content: &str, decls: &[&str]) -> Vec<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut repr_lines = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#[repr") {
            continue;
        }

        // Scan forward to the next non-empty, non-comment, non-attribute line.
        let mut j = idx + 1;
        // LOOP_PROOF: mode=condition; reason=Each skip advances to the next line of the finite input, and the first declaration ends the scan.;
        while j < lines.len() {
            let next = lines[j].trim();
            if next.is_empty() || next.starts_with("//") {
                j += 1;
                continue;
            }
            if next.starts_with('#') {
                j += 1;
                continue;
            }

            if decls.iter().any(|decl| next.starts_with(decl)) {
                repr_lines.push(trimmed.to_string());
            }
            break;
        }
    }

    repr_lines
}

// Simple FNV-1a 64-bit hash implementation
pub(super) struct Fnv1aHasher {
    state: u64,
}

impl Fnv1aHasher {
    pub(super) const fn new() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }

    pub(super) fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state ^= u64::from(b);
            self.state = self.state.wrapping_mul(0x0100_0000_01b3);
        }
    }

    pub(super) const fn finish(&self) -> u64 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> String {
        [
            include_str!("../src/driver_abi.rs"),
            include_str!("../src/driver_abi/task.rs"),
            include_str!("../src/driver_abi/time.rs"),
            include_str!("../src/driver_abi/block.rs"),
            include_str!("../src/balloon.rs"),
        ]
        .join("\n")
    }

    #[test]
    fn declaration_changes_in_each_foreign_input_change_identity() {
        let original = source();
        let hash = calculate_abi_hash(&original);
        for (before, after) in [
            (
                "pub struct KernelApiV4 {",
                "pub struct KernelApiV4 { pub added: u64,",
            ),
            (
                "pub struct AbiTaskOptions {",
                "pub struct AbiTaskOptions { pub added: u64,",
            ),
            (
                "pub struct AbiTimerStatistics {",
                "pub struct AbiTimerStatistics { pub added: u64,",
            ),
            (
                "pub struct AbiBlockSubmission {",
                "pub struct AbiBlockSubmission { pub added: u64,",
            ),
            (
                "pub struct AbiBalloonPage {",
                "pub struct AbiBalloonPage { pub added: u64,",
            ),
            (
                "fn(lease: u64, command: u8, device: u64, generation: u64)",
                "fn(lease: u64, command: u64, device: u64, generation: u64)",
            ),
        ] {
            assert!(
                original.contains(before),
                "fixture declaration absent: {before}"
            );
            assert_ne!(calculate_abi_hash(&original.replace(before, after)), hash);
        }
    }

    #[test]
    fn tuple_declaration_excludes_following_implementation() {
        let mut actual = Fnv1aHasher::new();
        extract_and_hash_decl(
            "pub struct Lease(u32);\nimpl Lease { fn extra() {} }",
            "pub struct Lease",
            &mut actual,
        );
        let mut expected = Fnv1aHasher::new();
        expected.write(b"pubstructLease(u32);");
        assert_eq!(actual.finish(), expected.finish());
    }

    #[test]
    #[should_panic(expected = "missing ABI declaration")]
    fn declaration_prefix_and_comment_cannot_substitute_for_a_required_type() {
        let mut hasher = Fnv1aHasher::new();
        extract_and_hash_decl(
            "// pub struct Lease(u32);\npub struct LeaseExtension(u32);",
            "pub struct Lease",
            &mut hasher,
        );
    }

    #[test]
    #[should_panic(expected = "unterminated ABI declaration")]
    fn truncated_declaration_is_not_published() {
        let mut hasher = Fnv1aHasher::new();
        extract_and_hash_decl(
            "pub struct Lease { pub field: u32",
            "pub struct Lease",
            &mut hasher,
        );
    }

    #[test]
    #[should_panic(expected = "missing ABI declaration")]
    fn incomplete_schema_is_not_published() {
        calculate_abi_hash("pub struct KernelApiV4 { pub field: u64 }");
    }
}
