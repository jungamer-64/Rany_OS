use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::aml::{
    AmlBudget, AmlNamespace, AmlNamespaceBuilder, AmlObject, AmlPath, AmlValue, AmlVm,
};
use crate::{
    AmlError, AmlErrorKind, CpuFirmwareEvent, GpeEvent, GpeNumber, GpeTrigger, TableCatalog,
    TableSignature,
};

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

/// Namespace object that either already contains a value or must be evaluated
/// by the AML worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamespaceBinding {
    Value(AmlValue),
    Method(AmlPath),
}

/// AML bindings owned by one processor object or `ACPI0007` device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuNamespaceBinding {
    pub path: AmlPath,
    pub uid: Option<NamespaceBinding>,
    pub mat: Option<NamespaceBinding>,
    pub proximity_domain: Option<NamespaceBinding>,
    pub status: Option<NamespaceBinding>,
    pub eject_method: Option<AmlPath>,
    pub ost_method: Option<AmlPath>,
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
    /// Returns a typed AML error when the namespace is unavailable or a CPU
    /// property is neither a value nor a control method.
    pub fn cpu_devices(&self) -> Result<Vec<CpuNamespaceBinding>, AmlError> {
        let namespace = self.namespace.as_ref().ok_or_else(|| match &self.state {
            AcpiRuntimeState::StaticTablesOnly { aml_error } => aml_error.clone(),
            AcpiRuntimeState::NamespaceReady => AmlError::new(
                AmlErrorKind::MissingObject,
                "ACPI namespace was not published",
            ),
        })?;
        let mut devices = Vec::new();
        for (path, object) in namespace.iter() {
            if is_cpu_device(namespace, path, object)? {
                devices.push(bind_cpu_device(namespace, path)?);
            }
        }
        Ok(devices)
    }

    /// Resolves the AML event method for one GPE number.
    ///
    /// # Errors
    ///
    /// Returns a typed firmware error when both edge and level methods exist,
    /// or an event-method name resolves to an object that is not a method.
    pub fn gpe_event(&self, number: GpeNumber) -> Result<Option<GpeEvent>, AmlError> {
        let namespace = self.namespace.as_ref().ok_or_else(|| {
            AmlError::new(
                AmlErrorKind::MissingObject,
                "ACPI AML namespace is unavailable",
            )
        })?;
        resolve_gpe_event(namespace, number)
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
        let id = self
            .next_vm_id
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                AmlError::new(
                    AmlErrorKind::AllocationBudgetExhausted,
                    "AML VM identifier space exhausted",
                )
            })?;
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

fn is_cpu_device(
    namespace: &AmlNamespace,
    path: &AmlPath,
    object: &AmlObject,
) -> Result<bool, AmlError> {
    if matches!(object, AmlObject::Processor(_)) {
        return Ok(true);
    }
    if !matches!(object, AmlObject::Device(_)) {
        return Ok(false);
    }
    let hid_path = path.child("_HID")?;
    Ok(matches!(
        namespace.get(&hid_path),
        Some(AmlObject::Value(AmlValue::String(hid))) if hid.as_ref() == "ACPI0007"
    ))
}

fn bind_cpu_device(
    namespace: &AmlNamespace,
    path: &AmlPath,
) -> Result<CpuNamespaceBinding, AmlError> {
    let uid_path = path.child("_UID")?;
    let mat_path = path.child("_MAT")?;
    let pxm_path = path.child("_PXM")?;
    let sta_path = path.child("_STA")?;
    let eject_path = path.child("_EJ0")?;
    let ost_path = path.child("_OST")?;

    Ok(CpuNamespaceBinding {
        path: path.clone(),
        uid: bind_value_or_method(namespace, &uid_path)?,
        mat: bind_value_or_method(namespace, &mat_path)?,
        proximity_domain: bind_value_or_method(namespace, &pxm_path)?,
        status: bind_value_or_method(namespace, &sta_path)?,
        eject_method: bind_method(namespace, eject_path)?,
        ost_method: bind_method(namespace, ost_path)?,
    })
}

fn bind_method(namespace: &AmlNamespace, path: AmlPath) -> Result<Option<AmlPath>, AmlError> {
    match namespace.get(&path) {
        None => Ok(None),
        Some(AmlObject::Method(_)) => Ok(Some(path)),
        Some(_) => Err(invalid_object(&path, "CPU control object must be a method")),
    }
}

fn bind_value_or_method(
    namespace: &AmlNamespace,
    path: &AmlPath,
) -> Result<Option<NamespaceBinding>, AmlError> {
    match namespace.get(path) {
        None => Ok(None),
        Some(AmlObject::Value(value)) => Ok(Some(NamespaceBinding::Value(value.clone()))),
        Some(AmlObject::Method(_)) => Ok(Some(NamespaceBinding::Method(path.clone()))),
        Some(_) => Err(invalid_object(
            path,
            "CPU property must be a value or control method",
        )),
    }
}

fn event_method_present(namespace: &AmlNamespace, path: &AmlPath) -> Result<bool, AmlError> {
    match namespace.get(path) {
        None => Ok(false),
        Some(AmlObject::Method(_)) => Ok(true),
        Some(_) => Err(invalid_object(path, "GPE event object must be a method")),
    }
}

fn resolve_gpe_event(
    namespace: &AmlNamespace,
    number: GpeNumber,
) -> Result<Option<GpeEvent>, AmlError> {
    let edge = GpeEvent {
        number,
        trigger: GpeTrigger::Edge,
    };
    let level = GpeEvent {
        number,
        trigger: GpeTrigger::Level,
    };
    let edge_present = event_method_present(namespace, &edge.method_path()?)?;
    let level_present = event_method_present(namespace, &level.method_path()?)?;
    match (edge_present, level_present) {
        (true, true) => Err(AmlError::new(
            AmlErrorKind::MalformedEncoding,
            "GPE has both edge-triggered and level-triggered event methods",
        )),
        (true, false) => Ok(Some(edge)),
        (false, true) => Ok(Some(level)),
        (false, false) => Ok(None),
    }
}

/// Decodes the evaluated `_UID` value of a processor device.
///
/// # Errors
///
/// Returns a typed object error for values other than Integer or String.
pub fn decode_firmware_uid(value: &AmlValue) -> Result<FirmwareUid, AmlError> {
    match value {
        AmlValue::Integer(value) => Ok(FirmwareUid::Integer(*value)),
        AmlValue::String(value) => Ok(FirmwareUid::String(value.clone())),
        _ => Err(AmlError::new(
            AmlErrorKind::InvalidObjectType,
            "_UID must evaluate to an Integer or String",
        )),
    }
}

/// Decodes the evaluated `_MAT` processor structure.
///
/// # Errors
///
/// Returns a typed object or encoding error when the value is not a Buffer or
/// does not contain a complete LAPIC/x2APIC processor structure.
pub fn decode_mat_processor(value: &AmlValue) -> Result<MatProcessor, AmlError> {
    parse_mat(value.as_buffer()?)
}

/// Decodes the evaluated `_PXM` proximity domain.
///
/// # Errors
///
/// Returns a typed object error when the value is not an Integer or exceeds
/// the firmware proximity-domain width.
pub fn decode_proximity_domain(value: &AmlValue) -> Result<u32, AmlError> {
    u32::try_from(value.as_integer()?).map_err(|_| {
        AmlError::new(
            AmlErrorKind::InvalidObjectType,
            "_PXM exceeds the u32 proximity-domain range",
        )
    })
}

/// Decodes the evaluated `_STA` bit field.
///
/// # Errors
///
/// Returns a typed object error when the value is not an Integer.
pub fn decode_device_status(value: &AmlValue) -> Result<u64, AmlError> {
    value.as_integer().map_err(|_| {
        AmlError::new(
            AmlErrorKind::InvalidObjectType,
            "_STA must evaluate to an Integer",
        )
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
        let error = decode_device_status(&AmlValue::String(Arc::from("present"))).unwrap_err();
        assert_eq!(error.kind, AmlErrorKind::InvalidObjectType);
    }

    #[test]
    fn cpu_binding_keeps_dynamic_sta_unevaluated() {
        let cpu = AmlPath::new(Arc::<str>::from("\\CPU2")).unwrap();
        let hid = cpu.child("_HID").unwrap();
        let sta = cpu.child("_STA").unwrap();
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(cpu.clone(), AmlObject::Device(AmlDevice))
            .unwrap();
        namespace
            .insert(
                hid,
                AmlObject::Value(AmlValue::String(Arc::from("ACPI0007"))),
            )
            .unwrap();
        namespace
            .insert(
                sta.clone(),
                AmlObject::Method(crate::aml::AmlMethod::instructions(0, [])),
            )
            .unwrap();

        let binding = bind_cpu_device(&namespace, &cpu).unwrap();
        assert_eq!(binding.status, Some(NamespaceBinding::Method(sta)));
    }

    #[test]
    fn non_cpu_devices_do_not_enter_cpu_enumeration() {
        let device = AmlPath::new(Arc::<str>::from("\\PCI0")).unwrap();
        let uid = device.child("_UID").unwrap();
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(device.clone(), AmlObject::Device(AmlDevice))
            .unwrap();
        namespace
            .insert(uid, AmlObject::Value(AmlValue::Buffer(Arc::from([1]))))
            .unwrap();

        assert!(!is_cpu_device(&namespace, &device, namespace.get(&device).unwrap()).unwrap());
    }

    #[test]
    fn gpe_cannot_have_both_edge_and_level_methods() {
        let number = GpeNumber::new(0x2a).unwrap();
        let edge = GpeEvent {
            number,
            trigger: GpeTrigger::Edge,
        }
        .method_path()
        .unwrap();
        let level = GpeEvent {
            number,
            trigger: GpeTrigger::Level,
        }
        .method_path()
        .unwrap();
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(
                edge,
                AmlObject::Method(crate::aml::AmlMethod::instructions(0, [])),
            )
            .unwrap();
        namespace
            .insert(
                level,
                AmlObject::Method(crate::aml::AmlMethod::instructions(0, [])),
            )
            .unwrap();

        assert_eq!(
            resolve_gpe_event(&namespace, number).unwrap_err().kind,
            AmlErrorKind::MalformedEncoding
        );
    }

    #[test]
    fn malformed_mat_length_is_rejected() {
        let error = parse_mat(&[9, 16, 0, 0]).unwrap_err();
        assert_eq!(error.kind, AmlErrorKind::MalformedEncoding);
    }
}
