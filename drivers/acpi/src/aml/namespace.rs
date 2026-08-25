use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::sync::Arc;

use crate::{AmlError, AmlErrorKind};

use super::{AmlInstruction, AmlValue};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AmlPath(Arc<str>);

impl AmlPath {
    /// Constructs an absolute AML namespace path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is not rooted or contains an invalid name
    /// segment.
    pub fn new(path: impl Into<Arc<str>>) -> Result<Self, AmlError> {
        let path = path.into();
        validate_path(&path)?;
        Ok(Self(path))
    }

    pub fn root() -> Self {
        Self(Arc::from("\\"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Appends one validated NameSeg to this path.
    ///
    /// # Errors
    ///
    /// Returns an error if `segment` is not a four-character AML NameSeg.
    pub fn child(&self, segment: &str) -> Result<Self, AmlError> {
        validate_segment(segment)?;
        let mut path = self.0.to_string();
        if path != "\\" {
            path.push('.');
        }
        path.push_str(segment);
        Self::new(Arc::<str>::from(path))
    }

    pub fn parent(&self) -> Self {
        if self.0.as_ref() == "\\" {
            return Self::root();
        }
        let parent = self.0.rsplit_once('.').map_or("\\", |(parent, _)| parent);
        Self(Arc::from(parent))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationRegionSpace {
    SystemMemory,
    SystemIo,
    PciConfig,
    EmbeddedController,
    SystemCmos,
    PciBarTarget,
    Ipmi,
    GeneralPurposeIo,
    GenericSerialBus,
    PlatformCommunicationsChannel,
    FunctionalFixedHardware,
    Oem(u8),
}

impl From<u8> for OperationRegionSpace {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::SystemMemory,
            0x01 => Self::SystemIo,
            0x02 => Self::PciConfig,
            0x03 => Self::EmbeddedController,
            0x05 => Self::SystemCmos,
            0x06 => Self::PciBarTarget,
            0x07 => Self::Ipmi,
            0x08 => Self::GeneralPurposeIo,
            0x09 => Self::GenericSerialBus,
            0x0a => Self::PlatformCommunicationsChannel,
            0x7f => Self::FunctionalFixedHardware,
            value => Self::Oem(value),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmlOperationRegion {
    pub space: OperationRegionSpace,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmlFieldAccess {
    Any,
    Byte,
    Word,
    DWord,
    QWord,
    Buffer,
    Reserved(u8),
}

impl From<u8> for AmlFieldAccess {
    fn from(value: u8) -> Self {
        match value & 0x0f {
            0 => Self::Any,
            1 => Self::Byte,
            2 => Self::Word,
            3 => Self::DWord,
            4 => Self::QWord,
            5 => Self::Buffer,
            value => Self::Reserved(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmlFieldUpdateRule {
    Preserve,
    WriteAsOnes,
    WriteAsZeros,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmlField {
    pub region: AmlPath,
    pub bit_offset: u64,
    pub bit_length: u64,
    pub access: AmlFieldAccess,
    pub lock: bool,
    pub update_rule: AmlFieldUpdateRule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmlDevice;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmlProcessor {
    pub processor_id: u8,
    pub pblk_address: u32,
    pub pblk_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmlMethodBody {
    Bytecode(Arc<[u8]>),
    Instructions(Arc<[AmlInstruction]>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmlMethod {
    pub argument_count: u8,
    pub serialized: bool,
    pub sync_level: u8,
    pub body: AmlMethodBody,
}

impl AmlMethod {
    pub fn instructions(
        argument_count: u8,
        instructions: impl Into<Arc<[AmlInstruction]>>,
    ) -> Self {
        Self {
            argument_count,
            serialized: false,
            sync_level: 0,
            body: AmlMethodBody::Instructions(instructions.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmlObject {
    Value(AmlValue),
    Method(AmlMethod),
    Device(AmlDevice),
    Processor(AmlProcessor),
    OperationRegion(AmlOperationRegion),
    Field(AmlField),
    Mutex { sync_level: u8 },
}

#[derive(Debug, Clone, Default)]
pub struct AmlNamespace {
    objects: BTreeMap<AmlPath, AmlObject>,
}

impl AmlNamespace {
    pub fn get(&self, path: &AmlPath) -> Option<&AmlObject> {
        self.objects.get(path)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&AmlPath, &AmlObject)> {
        self.objects.iter()
    }

    /// Inserts the single authoritative object for a namespace path.
    ///
    /// # Errors
    ///
    /// Returns an error if the path is already occupied.
    pub fn insert(&mut self, path: AmlPath, object: AmlObject) -> Result<(), AmlError> {
        if self.objects.contains_key(&path) {
            return Err(AmlError::object(
                AmlErrorKind::MalformedEncoding,
                Arc::from(path.as_str()),
                "duplicate AML namespace object",
            ));
        }
        self.objects.insert(path, object);
        Ok(())
    }

    pub(crate) fn method(&self, path: &AmlPath) -> Result<&AmlMethod, AmlError> {
        match self.objects.get(path) {
            Some(AmlObject::Method(method)) => Ok(method),
            Some(_) => Err(AmlError::object(
                AmlErrorKind::InvalidObjectType,
                Arc::from(path.as_str()),
                "AML object is not a method",
            )),
            None => Err(AmlError::object(
                AmlErrorKind::MissingObject,
                Arc::from(path.as_str()),
                "AML method is missing",
            )),
        }
    }
}

fn validate_path(path: &str) -> Result<(), AmlError> {
    if path == "\\" {
        return Ok(());
    }
    let Some(rest) = path.strip_prefix('\\') else {
        return Err(AmlError::new(
            AmlErrorKind::MalformedEncoding,
            "AML namespace path must be absolute",
        ));
    };
    if rest.is_empty() {
        return Ok(());
    }
    for segment in rest.split('.') {
        validate_segment(segment)?;
    }
    Ok(())
}

fn validate_segment(segment: &str) -> Result<(), AmlError> {
    let bytes = segment.as_bytes();
    if bytes.len() != 4
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(AmlError::new(
            AmlErrorKind::MalformedEncoding,
            "AML NameSeg must contain four uppercase ASCII, digit, or underscore bytes",
        ));
    }
    Ok(())
}
