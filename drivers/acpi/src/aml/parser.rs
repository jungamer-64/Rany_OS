use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{AmlError, AmlErrorKind};

use super::{
    AmlDevice, AmlField, AmlFieldAccess, AmlFieldUpdateRule, AmlMethod, AmlMethodBody,
    AmlNamespace, AmlObject, AmlOperationRegion, AmlPath, AmlProcessor, AmlValue,
    OperationRegionSpace,
};

pub struct AmlNamespaceBuilder {
    namespace: AmlNamespace,
}

impl AmlNamespaceBuilder {
    pub fn new() -> Self {
        Self {
            namespace: AmlNamespace::default(),
        }
    }

    /// Decodes one DSDT/SSDT AML byte stream into the shared namespace.
    ///
    /// # Errors
    ///
    /// Returns a typed AML error for malformed package lengths, invalid names,
    /// duplicate objects, invalid object encodings, or unsupported namespace
    /// opcodes.
    pub fn ingest(&mut self, aml: &[u8]) -> Result<(), AmlError> {
        let mut decoder = Decoder::new(aml);
        decoder.term_list(&mut self.namespace, &AmlPath::root(), aml.len())
    }

    pub fn finish(self) -> AmlNamespace {
        self.namespace
    }
}

impl Default for AmlNamespaceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn term_list(
        &mut self,
        namespace: &mut AmlNamespace,
        scope: &AmlPath,
        end: usize,
    ) -> Result<(), AmlError> {
        while self.cursor < end {
            let opcode = self.byte()?;
            match opcode {
                0x00 => {}
                0x08 => self.name_op(namespace, scope)?,
                0x10 => self.scope_op(namespace, scope)?,
                0x14 => self.method_op(namespace, scope)?,
                0x15 => self.external_op(scope)?,
                0x5b => self.extended_op(namespace, scope)?,
                value => return Err(AmlError::opcode(u16::from(value))),
            }
        }
        if self.cursor == end {
            Ok(())
        } else {
            Err(self.malformed("AML term crossed its enclosing package boundary"))
        }
    }

    fn name_op(&mut self, namespace: &mut AmlNamespace, scope: &AmlPath) -> Result<(), AmlError> {
        let path = self.name_string(scope)?;
        let value = self.data_object(scope)?;
        namespace.insert(path, AmlObject::Value(value))
    }

    fn scope_op(&mut self, namespace: &mut AmlNamespace, scope: &AmlPath) -> Result<(), AmlError> {
        let end = self.package_end()?;
        let path = self.name_string(scope)?;
        self.term_list(namespace, &path, end)
    }

    fn method_op(&mut self, namespace: &mut AmlNamespace, scope: &AmlPath) -> Result<(), AmlError> {
        let end = self.package_end()?;
        let path = self.name_string(scope)?;
        let flags = self.byte()?;
        if self.cursor > end {
            return Err(self.malformed("AML Method header exceeds package"));
        }
        let body = Arc::<[u8]>::from(
            self.bytes
                .get(self.cursor..end)
                .ok_or_else(|| self.malformed("AML Method body is truncated"))?,
        );
        self.cursor = end;
        namespace.insert(
            path,
            AmlObject::Method(AmlMethod {
                argument_count: flags & 0x07,
                serialized: flags & 0x08 != 0,
                sync_level: flags >> 4,
                body: AmlMethodBody::Bytecode(body),
            }),
        )
    }

    fn external_op(&mut self, scope: &AmlPath) -> Result<(), AmlError> {
        let _path = self.name_string(scope)?;
        let object_type = self.byte()?;
        if object_type == 0x08 {
            let _argument_count = self.byte()?;
        }
        Ok(())
    }

    fn extended_op(
        &mut self,
        namespace: &mut AmlNamespace,
        scope: &AmlPath,
    ) -> Result<(), AmlError> {
        let opcode = self.byte()?;
        match opcode {
            0x01 => {
                let path = self.name_string(scope)?;
                let sync_level = self.byte()? & 0x0f;
                namespace.insert(path, AmlObject::Mutex { sync_level })
            }
            0x80 => {
                let path = self.name_string(scope)?;
                let space = OperationRegionSpace::from(self.byte()?);
                let offset = self.integer_term(scope)?;
                let length = self.integer_term(scope)?;
                namespace.insert(
                    path,
                    AmlObject::OperationRegion(AmlOperationRegion {
                        space,
                        offset,
                        length,
                    }),
                )
            }
            0x81 => self.field_op(namespace, scope),
            0x82 => {
                let end = self.package_end()?;
                let path = self.name_string(scope)?;
                namespace.insert(path.clone(), AmlObject::Device(AmlDevice))?;
                self.term_list(namespace, &path, end)
            }
            0x83 => {
                let end = self.package_end()?;
                let path = self.name_string(scope)?;
                let processor_id = self.byte()?;
                let pblk_address = self.u32()?;
                let pblk_length = self.byte()?;
                namespace.insert(
                    path.clone(),
                    AmlObject::Processor(AmlProcessor {
                        processor_id,
                        pblk_address,
                        pblk_length,
                    }),
                )?;
                self.term_list(namespace, &path, end)
            }
            value => Err(AmlError::opcode(0x5b00 | u16::from(value))),
        }
    }

    fn field_op(&mut self, namespace: &mut AmlNamespace, scope: &AmlPath) -> Result<(), AmlError> {
        let end = self.package_end()?;
        let region = self.name_string(scope)?;
        let flags = self.byte()?;
        let mut access = AmlFieldAccess::from(flags);
        let lock = flags & 0x10 != 0;
        let update_rule = match (flags >> 5) & 0x03 {
            0 => AmlFieldUpdateRule::Preserve,
            1 => AmlFieldUpdateRule::WriteAsOnes,
            2 => AmlFieldUpdateRule::WriteAsZeros,
            _ => return Err(self.malformed("AML Field has a reserved update rule")),
        };
        let mut bit_offset = 0u64;
        while self.cursor < end {
            match self.peek()? {
                0x00 => {
                    self.cursor += 1;
                    bit_offset = bit_offset
                        .checked_add(self.package_length_u64()?)
                        .ok_or_else(|| self.malformed("AML Field bit offset overflowed"))?;
                }
                0x01 => {
                    self.cursor += 1;
                    access = AmlFieldAccess::from(self.byte()?);
                    let _access_attribute = self.byte()?;
                }
                0x02 => {
                    self.cursor += 1;
                    if self.peek()? == 0x11 {
                        let _connection = self.data_object(scope)?;
                    } else {
                        let _connection = self.name_string(scope)?;
                    }
                }
                0x03 => {
                    self.cursor += 1;
                    access = AmlFieldAccess::from(self.byte()?);
                    let _extended_attribute = self.byte()?;
                    let _access_length = self.byte()?;
                }
                _ => {
                    let name = self.name_segment()?;
                    let bit_length = self.package_length_u64()?;
                    let path = scope.child(&name)?;
                    namespace.insert(
                        path,
                        AmlObject::Field(AmlField {
                            region: region.clone(),
                            bit_offset,
                            bit_length,
                            access,
                            lock,
                            update_rule,
                        }),
                    )?;
                    bit_offset = bit_offset
                        .checked_add(bit_length)
                        .ok_or_else(|| self.malformed("AML Field bit offset overflowed"))?;
                }
            }
        }
        if self.cursor == end {
            Ok(())
        } else {
            Err(self.malformed("AML Field crossed its package boundary"))
        }
    }

    fn data_object(&mut self, scope: &AmlPath) -> Result<AmlValue, AmlError> {
        let opcode = self.peek()?;
        match opcode {
            0x00 => {
                self.cursor += 1;
                Ok(AmlValue::Integer(0))
            }
            0x01 => {
                self.cursor += 1;
                Ok(AmlValue::Integer(1))
            }
            0xff => {
                self.cursor += 1;
                Ok(AmlValue::Integer(u64::MAX))
            }
            0x0a => {
                self.cursor += 1;
                Ok(AmlValue::Integer(u64::from(self.byte()?)))
            }
            0x0b => {
                self.cursor += 1;
                Ok(AmlValue::Integer(u64::from(self.u16()?)))
            }
            0x0c => {
                self.cursor += 1;
                Ok(AmlValue::Integer(u64::from(self.u32()?)))
            }
            0x0e => {
                self.cursor += 1;
                Ok(AmlValue::Integer(self.u64()?))
            }
            0x0d => self.string_object(),
            0x11 => self.buffer_object(scope),
            0x12 | 0x13 => self.package_object(scope),
            value if is_name_string_start(value) => {
                self.name_string(scope).map(AmlValue::Reference)
            }
            value => Err(AmlError::opcode(u16::from(value))),
        }
    }

    fn integer_term(&mut self, scope: &AmlPath) -> Result<u64, AmlError> {
        self.data_object(scope)?.as_integer()
    }

    fn string_object(&mut self) -> Result<AmlValue, AmlError> {
        self.cursor += 1;
        let start = self.cursor;
        while self.peek()? != 0 {
            self.cursor += 1;
        }
        let bytes = self
            .bytes
            .get(start..self.cursor)
            .ok_or_else(|| self.malformed("AML string is truncated"))?;
        self.cursor += 1;
        let value =
            core::str::from_utf8(bytes).map_err(|_| self.malformed("AML string is not UTF-8"))?;
        Ok(AmlValue::String(Arc::from(value)))
    }

    fn buffer_object(&mut self, scope: &AmlPath) -> Result<AmlValue, AmlError> {
        self.cursor += 1;
        let end = self.package_end()?;
        let declared = usize::try_from(self.integer_term(scope)?)
            .map_err(|_| self.malformed("AML buffer length exceeds usize"))?;
        let available = end
            .checked_sub(self.cursor)
            .ok_or_else(|| self.malformed("AML buffer package underflow"))?;
        if declared > available {
            return Err(self.malformed("AML buffer initializer is shorter than declared length"));
        }
        let bytes = Arc::<[u8]>::from(
            self.bytes
                .get(self.cursor..self.cursor + declared)
                .ok_or_else(|| self.malformed("AML buffer data is truncated"))?,
        );
        self.cursor = end;
        Ok(AmlValue::Buffer(bytes))
    }

    fn package_object(&mut self, scope: &AmlPath) -> Result<AmlValue, AmlError> {
        self.cursor += 1;
        let end = self.package_end()?;
        let count = usize::from(self.byte()?);
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            if self.cursor >= end {
                return Err(self.malformed("AML package has fewer elements than declared"));
            }
            values.push(self.data_object(scope)?);
        }
        self.cursor = end;
        Ok(AmlValue::Package(values.into()))
    }

    fn name_string(&mut self, scope: &AmlPath) -> Result<AmlPath, AmlError> {
        let mut base = scope.clone();
        if self.peek()? == b'\\' {
            self.cursor += 1;
            base = AmlPath::root();
        } else {
            while self.peek()? == b'^' {
                self.cursor += 1;
                base = base.parent();
            }
        }

        let segment_count = match self.peek()? {
            0x00 => {
                self.cursor += 1;
                return Ok(base);
            }
            0x2e => {
                self.cursor += 1;
                2
            }
            0x2f => {
                self.cursor += 1;
                usize::from(self.byte()?)
            }
            _ => 1,
        };
        for _ in 0..segment_count {
            let segment = self.name_segment()?;
            base = base.child(&segment)?;
        }
        Ok(base)
    }

    fn name_segment(&mut self) -> Result<String, AmlError> {
        let bytes = self
            .bytes
            .get(self.cursor..self.cursor + 4)
            .ok_or_else(|| self.malformed("AML NameSeg is truncated"))?;
        self.cursor += 4;
        let segment =
            core::str::from_utf8(bytes).map_err(|_| self.malformed("AML NameSeg is not ASCII"))?;
        Ok(String::from(segment))
    }

    fn package_end(&mut self) -> Result<usize, AmlError> {
        let start = self.cursor;
        let length = self.package_length()?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| self.malformed("AML package length overflowed"))?;
        if end < self.cursor || end > self.bytes.len() {
            return Err(self.malformed("AML package extends beyond its table"));
        }
        Ok(end)
    }

    fn package_length_u64(&mut self) -> Result<u64, AmlError> {
        u64::try_from(self.package_length()?)
            .map_err(|_| self.malformed("AML package length exceeds u64"))
    }

    fn package_length(&mut self) -> Result<usize, AmlError> {
        let lead = self.byte()?;
        let follow_count = usize::from(lead >> 6);
        let mut length = usize::from(lead & if follow_count == 0 { 0x3f } else { 0x0f });
        for index in 0..follow_count {
            let follow = usize::from(self.byte()?);
            length |= follow << (4 + index * 8);
        }
        Ok(length)
    }

    fn byte(&mut self) -> Result<u8, AmlError> {
        let value = self.peek()?;
        self.cursor += 1;
        Ok(value)
    }

    fn peek(&self) -> Result<u8, AmlError> {
        self.bytes
            .get(self.cursor)
            .copied()
            .ok_or_else(|| self.malformed("unexpected end of AML stream"))
    }

    fn u16(&mut self) -> Result<u16, AmlError> {
        let bytes = self.take::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, AmlError> {
        let bytes = self.take::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, AmlError> {
        let bytes = self.take::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], AmlError> {
        let bytes = self
            .bytes
            .get(self.cursor..self.cursor + N)
            .ok_or_else(|| self.malformed("AML integer is truncated"))?;
        self.cursor += N;
        bytes
            .try_into()
            .map_err(|_| self.malformed("AML integer has invalid width"))
    }

    fn malformed(&self, detail: &'static str) -> AmlError {
        AmlError::new(AmlErrorKind::MalformedEncoding, detail)
    }
}

const fn is_name_string_start(value: u8) -> bool {
    matches!(value, b'\\' | b'^' | 0x2e | 0x2f | b'_' | b'A'..=b'Z')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_mat_buffer_is_a_typed_firmware_error() {
        let aml = [0x08, b'_', b'M', b'A', b'T', 0x11, 0x04, 0x0a, 0x04, 0xaa];
        let error = AmlNamespaceBuilder::new().ingest(&aml).unwrap_err();
        assert_eq!(error.kind, AmlErrorKind::MalformedEncoding);
    }

    #[test]
    fn processor_device_and_sta_enter_one_namespace() {
        let aml = [
            0x5b, 0x83, 0x12, b'C', b'P', b'U', b'2', 2, 0, 0, 0, 0, 0, 0x08, b'_', b'S', b'T',
            b'A', 0x0a, 0x0f,
        ];
        let mut package = Decoder::new(&aml);
        package.cursor = 2;
        assert_eq!(package.package_end().unwrap(), aml.len());
        let mut builder = AmlNamespaceBuilder::new();
        builder.ingest(&aml).unwrap();
        let namespace = builder.finish();
        let processor = AmlPath::new(Arc::<str>::from("\\CPU2")).unwrap();
        let sta = AmlPath::new(Arc::<str>::from("\\CPU2._STA")).unwrap();
        assert!(matches!(
            namespace.get(&processor),
            Some(AmlObject::Processor(_))
        ));
        assert_eq!(
            namespace.get(&sta),
            Some(&AmlObject::Value(AmlValue::Integer(0x0f)))
        );
    }

    #[test]
    fn field_declaration_preserves_region_geometry_and_write_policy() {
        let aml = [
            0x5b, 0x80, b'P', b'R', b'S', b'T', 0x01, 0x0b, 0xd8, 0x0c, 0x0a, 0x0c, 0x5b, 0x81,
            0x12, b'P', b'R', b'S', b'T', 0x03, b'C', b'S', b'E', b'L', 0x20, 0x00, 0x20, b'C',
            b'D', b'A', b'T', 0x20,
        ];
        let mut builder = AmlNamespaceBuilder::new();
        builder.ingest(&aml).unwrap();
        let namespace = builder.finish();
        let csel = AmlPath::new(Arc::<str>::from("\\CSEL")).unwrap();
        let cdat = AmlPath::new(Arc::<str>::from("\\CDAT")).unwrap();
        assert!(matches!(
            namespace.get(&csel),
            Some(AmlObject::Field(AmlField {
                bit_offset: 0,
                bit_length: 32,
                access: AmlFieldAccess::DWord,
                update_rule: AmlFieldUpdateRule::Preserve,
                ..
            }))
        ));
        assert!(matches!(
            namespace.get(&cdat),
            Some(AmlObject::Field(AmlField {
                bit_offset: 64,
                bit_length: 32,
                ..
            }))
        ));
    }
}
