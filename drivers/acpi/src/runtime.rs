use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::aml::{
    AmlBudget, AmlNamespace, AmlNamespaceBuilder, AmlObject, AmlPath, AmlValue, AmlVm,
};
use crate::{AmlError, AmlErrorKind, CpuFirmwareEvent, TableCatalog, TableSignature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcpiRuntimeState {
    StaticTablesOnly { aml_error: AmlError },
    NamespaceReady,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareUid {
    Integer(u64),
    String(Arc<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatProcessor {
    pub apic_id: u32,
    pub enabled: bool,
    pub online_capable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuNamespaceDevice {
    pub path: AmlPath,
    pub uid: Option<FirmwareUid>,
    pub mat: Option<MatProcessor>,
    pub proximity_domain: Option<u32>,
    pub status: u64,
    pub eject_method: Option<AmlPath>,
    pub ost_method: Option<AmlPath>,
}

impl CpuNamespaceDevice {
    pub const fn is_present(&self) -> bool {
        self.status & 0x01 != 0
    }

    pub const fn is_enabled(&self) -> bool {
        self.status & 0x02 != 0
    }
}

pub struct AcpiRuntime {
    catalog: Arc<TableCatalog>,
    namespace: Option<Arc<AmlNamespace>>,
    state: AcpiRuntimeState,
    next_vm_id: AtomicU64,
}

impl AcpiRuntime {
    pub fn new(catalog: TableCatalog) -> Self {
        let catalog = Arc::new(catalog);
        let namespace = build_namespace(&catalog);
        match namespace {
            Ok(namespace) => Self {
                catalog,
                namespace: Some(Arc::new(namespace)),
                state: AcpiRuntimeState::NamespaceReady,
                next_vm_id: AtomicU64::new(1),
            },
            Err(aml_error) => Self {
                catalog,
                namespace: None,
                state: AcpiRuntimeState::StaticTablesOnly { aml_error },
                next_vm_id: AtomicU64::new(1),
            },
        }
    }

    pub const fn state(&self) -> &AcpiRuntimeState {
        &self.state
    }

    pub fn catalog(&self) -> &TableCatalog {
        &self.catalog
    }

    pub fn namespace(&self) -> Option<&Arc<AmlNamespace>> {
        self.namespace.as_ref()
    }

    /// Enumerates processor objects and processor-device containers from the
    /// AML namespace without executing control methods.
    ///
    /// # Errors
    ///
    /// Returns a typed AML error when the namespace is unavailable, `_UID`,
    /// `_MAT`, `_PXM`, or `_STA` has an invalid type, or `_MAT` is malformed.
    pub fn cpu_devices(&self) -> Result<Vec<CpuNamespaceDevice>, AmlError> {
        let namespace = self.namespace.as_ref().ok_or_else(|| match &self.state {
            AcpiRuntimeState::StaticTablesOnly { aml_error } => aml_error.clone(),
            AcpiRuntimeState::NamespaceReady => AmlError::new(
                AmlErrorKind::MissingObject,
                "ACPI namespace was not published",
            ),
        })?;
        namespace
            .iter()
            .filter_map(|(path, object)| {
                matches!(object, AmlObject::Device(_) | AmlObject::Processor(_))
                    .then_some(read_cpu_device(namespace, path))
            })
            .collect()
    }

    /// Starts one budgeted AML method invocation.
    ///
    /// # Errors
    ///
    /// Returns a typed AML error if the namespace is unavailable, the VM ID
    /// space is exhausted, or method construction fails.
    pub fn invoke(
        &self,
        method: &AmlPath,
        arguments: &[AmlValue],
        budget: AmlBudget,
    ) -> Result<AmlVm, AmlError> {
        let namespace = self.namespace.as_ref().ok_or_else(|| {
            AmlError::new(
                AmlErrorKind::MissingObject,
                "ACPI AML namespace is unavailable",
            )
        })?;
        let id = self.next_vm_id.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err(AmlError::new(
                AmlErrorKind::AllocationBudgetExhausted,
                "AML VM identifier space exhausted",
            ));
        }
        AmlVm::new(id, namespace.clone(), method, arguments, budget)
    }

    pub fn notify_event(&self, object: AmlPath, value: u64) -> Option<CpuFirmwareEvent> {
        CpuFirmwareEvent::from_notify(object, value)
    }
}

fn build_namespace(catalog: &TableCatalog) -> Result<AmlNamespace, AmlError> {
    let mut builder = AmlNamespaceBuilder::new();
    if let Some(dsdt) = catalog.first(TableSignature::DSDT) {
        builder.ingest(dsdt.body())?;
    }
    for ssdt in catalog.matching(TableSignature::SSDT) {
        builder.ingest(ssdt.body())?;
    }
    Ok(builder.finish())
}

fn read_cpu_device(
    namespace: &AmlNamespace,
    path: &AmlPath,
) -> Result<CpuNamespaceDevice, AmlError> {
    let uid_path = path.child("_UID")?;
    let mat_path = path.child("_MAT")?;
    let pxm_path = path.child("_PXM")?;
    let sta_path = path.child("_STA")?;
    let eject_path = path.child("_EJ0")?;
    let ost_path = path.child("_OST")?;

    let uid = match namespace.get(&uid_path) {
        None => None,
        Some(AmlObject::Value(AmlValue::Integer(value))) => Some(FirmwareUid::Integer(*value)),
        Some(AmlObject::Value(AmlValue::String(value))) => Some(FirmwareUid::String(value.clone())),
        Some(_) => {
            return Err(invalid_object(
                &uid_path,
                "_UID must be an Integer or String",
            ));
        }
    };
    let mat = match namespace.get(&mat_path) {
        None => None,
        Some(AmlObject::Value(AmlValue::Buffer(value))) => Some(parse_mat(value)?),
        Some(_) => return Err(invalid_object(&mat_path, "_MAT must be a Buffer")),
    };
    let proximity_domain = match namespace.get(&pxm_path) {
        None => None,
        Some(AmlObject::Value(value)) => Some(
            u32::try_from(value.as_integer()?)
                .map_err(|_| invalid_object(&pxm_path, "_PXM exceeds u32"))?,
        ),
        Some(_) => return Err(invalid_object(&pxm_path, "_PXM must be an Integer")),
    };
    let status = match namespace.get(&sta_path) {
        None => 0x0f,
        Some(AmlObject::Value(value)) => value
            .as_integer()
            .map_err(|_| invalid_object(&sta_path, "_STA must evaluate to an Integer"))?,
        Some(AmlObject::Method(_)) => 0x0f,
        Some(_) => return Err(invalid_object(&sta_path, "_STA has an invalid object type")),
    };

    Ok(CpuNamespaceDevice {
        path: path.clone(),
        uid,
        mat,
        proximity_domain,
        status,
        eject_method: matches!(namespace.get(&eject_path), Some(AmlObject::Method(_)))
            .then_some(eject_path),
        ost_method: matches!(namespace.get(&ost_path), Some(AmlObject::Method(_)))
            .then_some(ost_path),
    })
}

fn parse_mat(bytes: &[u8]) -> Result<MatProcessor, AmlError> {
    let entry_type = bytes
        .first()
        .copied()
        .ok_or_else(|| AmlError::new(AmlErrorKind::MalformedEncoding, "_MAT buffer is empty"))?;
    let length = usize::from(*bytes.get(1).ok_or_else(|| {
        AmlError::new(
            AmlErrorKind::MalformedEncoding,
            "_MAT subtable length is missing",
        )
    })?);
    if length != bytes.len() {
        return Err(AmlError::new(
            AmlErrorKind::MalformedEncoding,
            "_MAT subtable length does not match buffer length",
        ));
    }
    match entry_type {
        0 if length >= 8 => {
            let flags = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| {
                AmlError::new(
                    AmlErrorKind::MalformedEncoding,
                    "_MAT LAPIC flags are truncated",
                )
            })?);
            Ok(MatProcessor {
                apic_id: u32::from(bytes[3]),
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
            })
        }
        9 if length >= 16 => {
            let apic_id = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| {
                AmlError::new(
                    AmlErrorKind::MalformedEncoding,
                    "_MAT x2APIC ID is truncated",
                )
            })?);
            let flags = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| {
                AmlError::new(
                    AmlErrorKind::MalformedEncoding,
                    "_MAT x2APIC flags are truncated",
                )
            })?);
            Ok(MatProcessor {
                apic_id,
                enabled: flags & 1 != 0,
                online_capable: flags & 2 != 0,
            })
        }
        _ => Err(AmlError::new(
            AmlErrorKind::InvalidObjectType,
            "_MAT is not a processor LAPIC/x2APIC structure",
        )),
    }
}

fn invalid_object(path: &AmlPath, detail: &'static str) -> AmlError {
    AmlError::object(
        AmlErrorKind::InvalidObjectType,
        Arc::from(path.as_str()),
        detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aml::{AmlDevice, AmlNamespace};

    #[test]
    fn non_integer_sta_is_rejected_without_panic() {
        let cpu = AmlPath::new(Arc::<str>::from("\\CPU2")).unwrap();
        let sta = cpu.child("_STA").unwrap();
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(cpu.clone(), AmlObject::Device(AmlDevice))
            .unwrap();
        namespace
            .insert(
                sta,
                AmlObject::Value(AmlValue::String(Arc::from("present"))),
            )
            .unwrap();
        let error = read_cpu_device(&namespace, &cpu).unwrap_err();
        assert_eq!(error.kind, AmlErrorKind::InvalidObjectType);
    }

    #[test]
    fn malformed_mat_length_is_rejected() {
        let error = parse_mat(&[9, 16, 0, 0]).unwrap_err();
        assert_eq!(error.kind, AmlErrorKind::MalformedEncoding);
    }
}
