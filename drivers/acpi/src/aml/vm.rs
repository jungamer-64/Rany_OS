use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{AmlError, AmlErrorKind};

use super::{
    AmlField, AmlFieldAccess, AmlFieldUpdateRule, AmlMethod, AmlMethodBody, AmlNamespace,
    AmlObject, AmlPath, AmlValue, OperationRegionSpace,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmlBudget {
    pub instructions: u64,
    pub loops: u64,
    pub recursion: u16,
    pub allocation_units: usize,
    pub deadline_tick: u64,
}

impl AmlBudget {
    pub const fn firmware_method(deadline_tick: u64) -> Self {
        Self {
            instructions: 100_000,
            loops: 10_000,
            recursion: 32,
            allocation_units: 1024 * 1024,
            deadline_tick,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmlInstruction {
    Push(AmlValue),
    LoadArgument(u8),
    LoadLocal(u8),
    StoreLocal(u8),
    IncrementLocal(u8),
    LoadName(AmlPath),
    StoreName(AmlPath),
    CreateName(AmlPath),
    LoadPackageElement(AmlPath),
    StorePackageElement(AmlPath),
    Discard,
    Equal,
    Less,
    LogicalAnd,
    BitAnd,
    BitOr,
    LogicalNot,
    Jump(usize),
    JumpIfFalse(usize),
    Call {
        method: AmlPath,
        arguments: u8,
    },
    Sleep {
        ticks: u64,
    },
    Acquire {
        mutex: AmlPath,
        timeout_millis: u16,
    },
    Release {
        mutex: AmlPath,
    },
    Notify {
        object: AmlPath,
    },
    RegionRead {
        region: AmlPath,
        offset: u64,
        width: u8,
    },
    RegionWrite {
        region: AmlPath,
        offset: u64,
        width: u8,
    },
    Return,
}

pub trait OperationRegionHandler: Sync {
    /// Reads one field from an ACPI OperationRegion.
    ///
    /// # Errors
    ///
    /// Returns a typed operation-region error when the address space, offset,
    /// or access width is unsupported or the underlying device access fails.
    fn read(
        &self,
        space: OperationRegionSpace,
        base: u64,
        region_length: u64,
        offset: u64,
        width: u8,
    ) -> Result<u64, AmlError>;

    /// Writes one field in an ACPI OperationRegion.
    ///
    /// # Errors
    ///
    /// Returns a typed operation-region error when the address space, offset,
    /// access width, or value is invalid, or the device access fails.
    fn write(
        &self,
        space: OperationRegionSpace,
        base: u64,
        region_length: u64,
        offset: u64,
        width: u8,
        value: u64,
    ) -> Result<(), AmlError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmWait {
    Sleep { until_tick: u64 },
    Mutex { path: AmlPath, timeout_tick: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmProgress {
    Complete(AmlValue),
    Waiting(VmWait),
    Notify { object: AmlPath, value: u64 },
}

#[derive(Debug, Default)]
pub struct VmEnvironment {
    mutex_owners: BTreeMap<AmlPath, MutexOwner>,
}

#[derive(Debug, Clone, Copy)]
struct MutexOwner {
    vm: u64,
    depth: u32,
}

impl VmEnvironment {
    fn acquire(&mut self, path: &AmlPath, owner: u64) -> Result<bool, AmlError> {
        match self.mutex_owners.get_mut(path) {
            None => {
                self.mutex_owners.insert(
                    path.clone(),
                    MutexOwner {
                        vm: owner,
                        depth: 1,
                    },
                );
                Ok(true)
            }
            Some(current) if current.vm == owner => {
                current.depth = current.depth.checked_add(1).ok_or_else(|| {
                    AmlError::object(
                        AmlErrorKind::Mutex,
                        Arc::from(path.as_str()),
                        "AML mutex acquisition depth overflowed",
                    )
                })?;
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    fn release(&mut self, path: &AmlPath, owner: u64) -> Result<(), AmlError> {
        match self.mutex_owners.get_mut(path) {
            Some(current) if current.vm == owner && current.depth > 1 => {
                current.depth -= 1;
                return Ok(());
            }
            Some(current) if current.vm == owner => {}
            _ => {
                return Err(AmlError::object(
                    AmlErrorKind::Mutex,
                    Arc::from(path.as_str()),
                    "AML method attempted to release a mutex it does not own",
                ));
            }
        }
        self.mutex_owners.remove(path);
        Ok(())
    }

    fn release_all(&mut self, owner: u64) {
        self.mutex_owners.retain(|_, current| current.vm != owner);
    }
}

struct Frame {
    instructions: Arc<[AmlInstruction]>,
    pc: usize,
    arguments: [AmlValue; 7],
    locals: [AmlValue; 8],
    named_values: BTreeMap<AmlPath, AmlValue>,
}

impl Frame {
    fn new(instructions: Arc<[AmlInstruction]>, arguments: &[AmlValue]) -> Self {
        let mut frame = Self {
            instructions,
            pc: 0,
            arguments: core::array::from_fn(|_| AmlValue::None),
            locals: core::array::from_fn(|_| AmlValue::None),
            named_values: BTreeMap::new(),
        };
        for (destination, source) in frame.arguments.iter_mut().zip(arguments.iter()) {
            *destination = source.clone();
        }
        frame
    }
}

pub struct AmlVm {
    id: u64,
    namespace: Arc<AmlNamespace>,
    frames: Vec<Frame>,
    values: Vec<AmlValue>,
    budget: AmlBudget,
    waiting: Option<VmWait>,
}

impl AmlVm {
    /// Creates a resumable invocation of one AML method.
    ///
    /// # Errors
    ///
    /// Returns an error if the method is missing, the target is not a method,
    /// the argument count is wrong, or its AML bytecode contains an unsupported
    /// instruction.
    pub fn new(
        id: u64,
        namespace: Arc<AmlNamespace>,
        method: &AmlPath,
        arguments: &[AmlValue],
        budget: AmlBudget,
    ) -> Result<Self, AmlError> {
        let method_path = method;
        let method = namespace.method(method_path)?;
        if arguments.len() != usize::from(method.argument_count) {
            return Err(AmlError::new(
                AmlErrorKind::InvalidObjectType,
                "AML method argument count does not match declaration",
            ));
        }
        let mut budget = budget;
        let instructions = compile_method(&namespace, method_path, method, &mut budget)?;
        Ok(Self {
            id,
            namespace,
            frames: alloc::vec![Frame::new(instructions, arguments)],
            values: Vec::new(),
            budget,
            waiting: None,
        })
    }

    /// Resumes execution until completion, an asynchronous wait, or Notify.
    ///
    /// # Errors
    ///
    /// Returns typed errors for exhausted budgets, deadline expiry, malformed
    /// stack state, missing namespace objects, mutex violations, or failed
    /// OperationRegion access.
    pub fn resume(
        &mut self,
        now_tick: u64,
        environment: &mut VmEnvironment,
        regions: Option<&dyn OperationRegionHandler>,
    ) -> Result<VmProgress, AmlError> {
        let result = self.resume_inner(now_tick, environment, regions);
        if result.is_err() || matches!(&result, Ok(VmProgress::Complete(_))) {
            environment.release_all(self.id);
        }
        result
    }

    fn resume_inner(
        &mut self,
        now_tick: u64,
        environment: &mut VmEnvironment,
        regions: Option<&dyn OperationRegionHandler>,
    ) -> Result<VmProgress, AmlError> {
        if now_tick > self.budget.deadline_tick {
            return Err(AmlError::new(
                AmlErrorKind::TimedOut,
                "AML method exceeded its time deadline",
            ));
        }
        if let Some(waiting) = self.waiting.clone() {
            match waiting {
                VmWait::Sleep { until_tick } if now_tick < until_tick => {
                    return Ok(VmProgress::Waiting(waiting));
                }
                VmWait::Mutex { timeout_tick, .. } if now_tick > timeout_tick => {
                    return Err(AmlError::new(
                        AmlErrorKind::TimedOut,
                        "AML mutex acquisition timed out",
                    ));
                }
                VmWait::Sleep { .. } => self.waiting = None,
                VmWait::Mutex { .. } => {}
            }
        }

        loop {
            self.consume_instruction()?;
            if self.frames.is_empty() {
                return Ok(VmProgress::Complete(
                    self.values.pop().unwrap_or(AmlValue::None),
                ));
            }
            let instruction = {
                let frame = self
                    .frames
                    .last_mut()
                    .ok_or_else(|| invalid_vm("AML call frame disappeared"))?;
                let instruction = frame.instructions.get(frame.pc).cloned();
                if instruction.is_some() {
                    frame.pc += 1;
                }
                instruction
            };
            let Some(instruction) = instruction else {
                let value = AmlValue::None;
                self.frames.pop();
                if self.frames.is_empty() {
                    return Ok(VmProgress::Complete(value));
                }
                self.values.push(value);
                continue;
            };
            match instruction {
                AmlInstruction::Push(value) => {
                    self.consume_allocation(value.allocation_units())?;
                    self.values.push(value);
                }
                AmlInstruction::LoadArgument(index) => {
                    let value = self
                        .frames
                        .last()
                        .ok_or_else(|| invalid_vm("AML argument has no call frame"))?
                        .arguments
                        .get(usize::from(index))
                        .cloned()
                        .ok_or_else(|| invalid_vm("AML argument index is out of range"))?;
                    self.values.push(value);
                }
                AmlInstruction::LoadLocal(index) => {
                    let value = self
                        .frames
                        .last()
                        .ok_or_else(|| invalid_vm("AML local has no call frame"))?
                        .locals
                        .get(usize::from(index))
                        .cloned()
                        .ok_or_else(|| invalid_vm("AML local index is out of range"))?;
                    self.values.push(value);
                }
                AmlInstruction::StoreLocal(index) => {
                    let value = self.pop_value()?;
                    let destination = self
                        .frames
                        .last_mut()
                        .ok_or_else(|| invalid_vm("AML local has no call frame"))?
                        .locals
                        .get_mut(usize::from(index))
                        .ok_or_else(|| invalid_vm("AML local index is out of range"))?;
                    *destination = value;
                }
                AmlInstruction::IncrementLocal(index) => {
                    let destination = self
                        .frames
                        .last_mut()
                        .ok_or_else(|| invalid_vm("AML local has no call frame"))?
                        .locals
                        .get_mut(usize::from(index))
                        .ok_or_else(|| invalid_vm("AML local index is out of range"))?;
                    *destination = AmlValue::Integer(
                        destination
                            .as_integer()?
                            .checked_add(1)
                            .ok_or_else(|| invalid_vm("AML Increment overflowed"))?,
                    );
                }
                AmlInstruction::LoadName(path) => {
                    let value = match self
                        .frames
                        .last()
                        .and_then(|frame| frame.named_values.get(&path))
                        .cloned()
                    {
                        Some(value) => value,
                        None => self.read_named_value(&path, regions)?,
                    };
                    self.values.push(value);
                }
                AmlInstruction::StoreName(path) => {
                    let value = self.pop_value()?.as_integer()?;
                    let dynamic = self
                        .frames
                        .last_mut()
                        .and_then(|frame| frame.named_values.get_mut(&path));
                    if let Some(destination) = dynamic {
                        *destination = AmlValue::Integer(value);
                    } else {
                        self.write_named_integer(&path, value, regions)?;
                    }
                }
                AmlInstruction::CreateName(path) => {
                    let value = self.pop_value()?;
                    self.consume_allocation(
                        path.as_str()
                            .len()
                            .saturating_add(core::mem::size_of::<AmlValue>()),
                    )?;
                    let frame = self
                        .frames
                        .last_mut()
                        .ok_or_else(|| invalid_vm("AML named value has no call frame"))?;
                    if frame.named_values.insert(path.clone(), value).is_some() {
                        return Err(AmlError::object(
                            AmlErrorKind::MalformedEncoding,
                            Arc::from(path.as_str()),
                            "AML method created the same named value twice",
                        ));
                    }
                }
                AmlInstruction::LoadPackageElement(path) => {
                    let index = usize::try_from(self.pop_value()?.as_integer()?)
                        .map_err(|_| invalid_vm("AML package index exceeds usize"))?;
                    let value = self.package_element(&path, index)?.clone();
                    self.values.push(value);
                }
                AmlInstruction::StorePackageElement(path) => {
                    let index = usize::try_from(self.pop_value()?.as_integer()?)
                        .map_err(|_| invalid_vm("AML package index exceeds usize"))?;
                    let value = self.pop_value()?;
                    let package_len = self.package(&path)?.len();
                    self.consume_allocation(package_len)?;
                    let package = self.package_mut(&path)?;
                    let destination = package
                        .get_mut(index)
                        .ok_or_else(|| invalid_vm("AML package index is out of range"))?;
                    *destination = value;
                }
                AmlInstruction::Discard => {
                    let _ = self.pop_value()?;
                }
                AmlInstruction::Equal => {
                    let right = self.pop_value()?;
                    let left = self.pop_value()?;
                    self.values
                        .push(AmlValue::Integer(u64::from(left == right)));
                }
                AmlInstruction::Less => {
                    let right = self.pop_value()?.as_integer()?;
                    let left = self.pop_value()?.as_integer()?;
                    self.values.push(AmlValue::Integer(u64::from(left < right)));
                }
                AmlInstruction::LogicalAnd => {
                    let right = self.pop_value()?.truthy()?;
                    let left = self.pop_value()?.truthy()?;
                    self.values
                        .push(AmlValue::Integer(u64::from(left && right)));
                }
                AmlInstruction::BitAnd => self.binary_integer(|left, right| left & right)?,
                AmlInstruction::BitOr => self.binary_integer(|left, right| left | right)?,
                AmlInstruction::LogicalNot => {
                    let value = self.pop_value()?.truthy()?;
                    self.values.push(AmlValue::Integer(u64::from(!value)));
                }
                AmlInstruction::Jump(target) => self.jump(target)?,
                AmlInstruction::JumpIfFalse(target) => {
                    if !self.pop_value()?.truthy()? {
                        self.jump(target)?;
                    }
                }
                AmlInstruction::Call { method, arguments } => {
                    if self.frames.len() >= usize::from(self.budget.recursion) {
                        return Err(AmlError::new(
                            AmlErrorKind::RecursionBudgetExhausted,
                            "AML recursion budget exhausted",
                        ));
                    }
                    let mut call_arguments = Vec::with_capacity(usize::from(arguments));
                    for _ in 0..arguments {
                        call_arguments.push(self.pop_value()?);
                    }
                    call_arguments.reverse();
                    let method_object = self.namespace.method(&method)?;
                    if method_object.argument_count != arguments {
                        return Err(invalid_vm("AML call argument count does not match method"));
                    }
                    let instructions =
                        compile_method(&self.namespace, &method, method_object, &mut self.budget)?;
                    self.frames.push(Frame::new(instructions, &call_arguments));
                }
                AmlInstruction::Sleep { ticks } => {
                    let waiting = VmWait::Sleep {
                        until_tick: now_tick.saturating_add(ticks),
                    };
                    self.waiting = Some(waiting.clone());
                    return Ok(VmProgress::Waiting(waiting));
                }
                AmlInstruction::Acquire {
                    mutex,
                    timeout_millis,
                } => {
                    if environment.acquire(&mutex, self.id)? {
                        self.waiting = None;
                    } else {
                        let frame = self
                            .frames
                            .last_mut()
                            .ok_or_else(|| invalid_vm("AML mutex has no call frame"))?;
                        frame.pc = frame.pc.saturating_sub(1);
                        let timeout_tick = match self.waiting.take() {
                            Some(VmWait::Mutex { path, timeout_tick }) if path == mutex => {
                                timeout_tick
                            }
                            _ if timeout_millis == u16::MAX => self.budget.deadline_tick,
                            _ => now_tick.saturating_add(u64::from(timeout_millis)),
                        };
                        let waiting = VmWait::Mutex {
                            path: mutex,
                            timeout_tick,
                        };
                        self.waiting = Some(waiting.clone());
                        return Ok(VmProgress::Waiting(waiting));
                    }
                }
                AmlInstruction::Release { mutex } => environment.release(&mutex, self.id)?,
                AmlInstruction::Notify { object } => {
                    let value = self.pop_value()?.as_integer()?;
                    return Ok(VmProgress::Notify { object, value });
                }
                AmlInstruction::RegionRead {
                    region,
                    offset,
                    width,
                } => {
                    let handler = regions.ok_or_else(|| {
                        AmlError::new(
                            AmlErrorKind::OperationRegion,
                            "OperationRegion handler is unavailable",
                        )
                    })?;
                    let AmlObject::OperationRegion(region_object) = self
                        .namespace
                        .get(&region)
                        .ok_or_else(|| missing_region(&region))?
                    else {
                        return Err(missing_region(&region));
                    };
                    self.values.push(AmlValue::Integer(handler.read(
                        region_object.space,
                        region_object.offset,
                        region_object.length,
                        offset,
                        width,
                    )?));
                }
                AmlInstruction::RegionWrite {
                    region,
                    offset,
                    width,
                } => {
                    let value = self.pop_value()?.as_integer()?;
                    let handler = regions.ok_or_else(|| {
                        AmlError::new(
                            AmlErrorKind::OperationRegion,
                            "OperationRegion handler is unavailable",
                        )
                    })?;
                    let AmlObject::OperationRegion(region_object) = self
                        .namespace
                        .get(&region)
                        .ok_or_else(|| missing_region(&region))?
                    else {
                        return Err(missing_region(&region));
                    };
                    handler.write(
                        region_object.space,
                        region_object.offset,
                        region_object.length,
                        offset,
                        width,
                        value,
                    )?;
                }
                AmlInstruction::Return => {
                    let value = self.values.pop().unwrap_or(AmlValue::None);
                    self.frames.pop();
                    if self.frames.is_empty() {
                        return Ok(VmProgress::Complete(value));
                    }
                    self.values.push(value);
                }
            }
        }
    }

    fn consume_instruction(&mut self) -> Result<(), AmlError> {
        self.budget.instructions = self.budget.instructions.checked_sub(1).ok_or_else(|| {
            AmlError::new(
                AmlErrorKind::InstructionBudgetExhausted,
                "AML instruction budget exhausted",
            )
        })?;
        Ok(())
    }

    fn consume_allocation(&mut self, units: usize) -> Result<(), AmlError> {
        self.budget.allocation_units =
            self.budget
                .allocation_units
                .checked_sub(units)
                .ok_or_else(|| {
                    AmlError::new(
                        AmlErrorKind::AllocationBudgetExhausted,
                        "AML allocation budget exhausted",
                    )
                })?;
        Ok(())
    }

    fn pop_value(&mut self) -> Result<AmlValue, AmlError> {
        self.values
            .pop()
            .ok_or_else(|| invalid_vm("AML operand stack is empty"))
    }

    fn binary_integer(&mut self, operation: impl FnOnce(u64, u64) -> u64) -> Result<(), AmlError> {
        let right = self.pop_value()?.as_integer()?;
        let left = self.pop_value()?.as_integer()?;
        self.values.push(AmlValue::Integer(operation(left, right)));
        Ok(())
    }

    fn package(&self, path: &AmlPath) -> Result<&[AmlValue], AmlError> {
        match self
            .frames
            .last()
            .and_then(|frame| frame.named_values.get(path))
        {
            Some(AmlValue::Package(values)) => Ok(values),
            Some(_) => Err(AmlError::object(
                AmlErrorKind::InvalidObjectType,
                Arc::from(path.as_str()),
                "AML named value is not a package",
            )),
            None => Err(AmlError::object(
                AmlErrorKind::MissingObject,
                Arc::from(path.as_str()),
                "AML method-local package is missing",
            )),
        }
    }

    fn package_mut(&mut self, path: &AmlPath) -> Result<&mut [AmlValue], AmlError> {
        match self
            .frames
            .last_mut()
            .and_then(|frame| frame.named_values.get_mut(path))
        {
            Some(AmlValue::Package(values)) => Ok(Arc::make_mut(values)),
            Some(_) => Err(AmlError::object(
                AmlErrorKind::InvalidObjectType,
                Arc::from(path.as_str()),
                "AML named value is not a package",
            )),
            None => Err(AmlError::object(
                AmlErrorKind::MissingObject,
                Arc::from(path.as_str()),
                "AML method-local package is missing",
            )),
        }
    }

    fn package_element(&self, path: &AmlPath, index: usize) -> Result<&AmlValue, AmlError> {
        self.package(path)?
            .get(index)
            .ok_or_else(|| invalid_vm("AML package index is out of range"))
    }

    fn read_named_value(
        &mut self,
        path: &AmlPath,
        regions: Option<&dyn OperationRegionHandler>,
    ) -> Result<AmlValue, AmlError> {
        let mut path = path.clone();
        let mut visited = BTreeSet::new();
        loop {
            self.consume_allocation(path.as_str().len())?;
            if !visited.insert(path.clone()) {
                return Err(AmlError::object(
                    AmlErrorKind::MalformedEncoding,
                    Arc::from(path.as_str()),
                    "AML namespace reference cycle detected",
                ));
            }
            match self.namespace.get(&path).cloned() {
                Some(AmlObject::Value(AmlValue::Reference(target))) => path = target,
                Some(AmlObject::Value(value)) => return Ok(value),
                Some(AmlObject::Field(field)) => {
                    return self
                        .read_field(&path, &field, regions)
                        .map(AmlValue::Integer);
                }
                Some(_) => {
                    return Err(AmlError::object(
                        AmlErrorKind::InvalidObjectType,
                        Arc::from(path.as_str()),
                        "AML object cannot be loaded as a value",
                    ));
                }
                None => {
                    return Err(AmlError::object(
                        AmlErrorKind::MissingObject,
                        Arc::from(path.as_str()),
                        "AML namespace object is missing",
                    ));
                }
            }
        }
    }

    fn write_named_integer(
        &mut self,
        path: &AmlPath,
        value: u64,
        regions: Option<&dyn OperationRegionHandler>,
    ) -> Result<(), AmlError> {
        match self.namespace.get(path).cloned() {
            Some(AmlObject::Field(field)) => self.write_field(path, &field, value, regions),
            Some(_) => Err(AmlError::object(
                AmlErrorKind::InvalidObjectType,
                Arc::from(path.as_str()),
                "AML object is not a writable field",
            )),
            None => Err(AmlError::object(
                AmlErrorKind::MissingObject,
                Arc::from(path.as_str()),
                "AML store target is missing",
            )),
        }
    }

    fn read_field(
        &self,
        path: &AmlPath,
        field: &AmlField,
        regions: Option<&dyn OperationRegionHandler>,
    ) -> Result<u64, AmlError> {
        let (handler, region, access_width) = self.field_access(path, field, regions)?;
        let mut bit = field.bit_offset;
        let mut remaining = field.bit_length;
        let mut destination_bit = 0u32;
        let mut result = 0u64;
        while remaining != 0 {
            let unit_width = u64::from(access_width);
            let unit_start = bit / unit_width * unit_width;
            let bit_in_unit = bit - unit_start;
            let chunk = remaining.min(unit_width - bit_in_unit);
            let raw = handler.read(
                region.space,
                region.offset,
                region.length,
                unit_start / 8,
                access_width,
            )?;
            let chunk_width = u32::try_from(chunk)
                .map_err(|_| invalid_vm("AML field chunk width exceeds u32"))?;
            let source_bit = u32::try_from(bit_in_unit)
                .map_err(|_| invalid_vm("AML field bit offset exceeds u32"))?;
            result |= ((raw >> source_bit) & low_mask(chunk_width)) << destination_bit;
            bit = bit
                .checked_add(chunk)
                .ok_or_else(|| invalid_vm("AML field bit offset overflowed"))?;
            remaining -= chunk;
            destination_bit += chunk_width;
        }
        Ok(result)
    }

    fn write_field(
        &self,
        path: &AmlPath,
        field: &AmlField,
        value: u64,
        regions: Option<&dyn OperationRegionHandler>,
    ) -> Result<(), AmlError> {
        let (handler, region, access_width) = self.field_access(path, field, regions)?;
        let mut bit = field.bit_offset;
        let mut remaining = field.bit_length;
        let mut source_bit = 0u32;
        while remaining != 0 {
            let unit_width = u64::from(access_width);
            let unit_start = bit / unit_width * unit_width;
            let bit_in_unit = bit - unit_start;
            let chunk = remaining.min(unit_width - bit_in_unit);
            let chunk_width = u32::try_from(chunk)
                .map_err(|_| invalid_vm("AML field chunk width exceeds u32"))?;
            let destination_bit = u32::try_from(bit_in_unit)
                .map_err(|_| invalid_vm("AML field bit offset exceeds u32"))?;
            let access_mask = low_mask(u32::from(access_width));
            let mut raw = match field.update_rule {
                AmlFieldUpdateRule::Preserve => handler.read(
                    region.space,
                    region.offset,
                    region.length,
                    unit_start / 8,
                    access_width,
                )?,
                AmlFieldUpdateRule::WriteAsOnes => access_mask,
                AmlFieldUpdateRule::WriteAsZeros => 0,
            };
            let destination_mask = low_mask(chunk_width) << destination_bit;
            let source = ((value >> source_bit) & low_mask(chunk_width)) << destination_bit;
            raw = (raw & !destination_mask) | source;
            handler.write(
                region.space,
                region.offset,
                region.length,
                unit_start / 8,
                access_width,
                raw & access_mask,
            )?;
            bit = bit
                .checked_add(chunk)
                .ok_or_else(|| invalid_vm("AML field bit offset overflowed"))?;
            remaining -= chunk;
            source_bit += chunk_width;
        }
        Ok(())
    }

    fn field_access<'a>(
        &self,
        path: &AmlPath,
        field: &AmlField,
        regions: Option<&'a dyn OperationRegionHandler>,
    ) -> Result<
        (
            &'a dyn OperationRegionHandler,
            super::AmlOperationRegion,
            u8,
        ),
        AmlError,
    > {
        if field.bit_length == 0 || field.bit_length > 64 {
            return Err(AmlError::object(
                AmlErrorKind::OperationRegion,
                Arc::from(path.as_str()),
                "AML integer field width must be between 1 and 64 bits",
            ));
        }
        if field.lock {
            return Err(AmlError::object(
                AmlErrorKind::OperationRegion,
                Arc::from(path.as_str()),
                "AML LockRule field access is unsupported",
            ));
        }
        let access_width = match field.access {
            AmlFieldAccess::Byte => 8,
            AmlFieldAccess::Word => 16,
            AmlFieldAccess::DWord => 32,
            AmlFieldAccess::QWord => 64,
            AmlFieldAccess::Any | AmlFieldAccess::Buffer | AmlFieldAccess::Reserved(_) => {
                return Err(AmlError::object(
                    AmlErrorKind::OperationRegion,
                    Arc::from(path.as_str()),
                    "AML field access type is unsupported",
                ));
            }
        };
        let region = match self.namespace.get(&field.region) {
            Some(AmlObject::OperationRegion(region)) => region.clone(),
            _ => return Err(missing_region(&field.region)),
        };
        let handler = regions.ok_or_else(|| {
            AmlError::new(
                AmlErrorKind::OperationRegion,
                "OperationRegion handler is unavailable",
            )
        })?;
        Ok((handler, region, access_width))
    }

    fn jump(&mut self, target: usize) -> Result<(), AmlError> {
        let frame = self
            .frames
            .last_mut()
            .ok_or_else(|| invalid_vm("AML jump has no call frame"))?;
        if target > frame.instructions.len() {
            return Err(invalid_vm("AML jump target is out of range"));
        }
        if target < frame.pc {
            self.budget.loops = self.budget.loops.checked_sub(1).ok_or_else(|| {
                AmlError::new(
                    AmlErrorKind::LoopBudgetExhausted,
                    "AML loop budget exhausted",
                )
            })?;
        }
        frame.pc = target;
        Ok(())
    }
}

const fn low_mask(width: u32) -> u64 {
    if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}

fn compile_method(
    namespace: &AmlNamespace,
    method_path: &AmlPath,
    method: &AmlMethod,
    budget: &mut AmlBudget,
) -> Result<Arc<[AmlInstruction]>, AmlError> {
    match &method.body {
        AmlMethodBody::Instructions(instructions) => Ok(instructions.clone()),
        AmlMethodBody::Bytecode(bytes) => {
            let scope = method_path.parent();
            let units_per_byte = core::mem::size_of::<AmlInstruction>()
                .checked_add(scope.as_str().len())
                .and_then(|units| units.checked_add(1))
                .ok_or_else(|| {
                    AmlError::new(
                        AmlErrorKind::AllocationBudgetExhausted,
                        "AML compiler reservation overflowed",
                    )
                })?;
            let reservation = bytes.len().checked_mul(units_per_byte).ok_or_else(|| {
                AmlError::new(
                    AmlErrorKind::AllocationBudgetExhausted,
                    "AML compiler reservation overflowed",
                )
            })?;
            budget.allocation_units = budget
                .allocation_units
                .checked_sub(reservation)
                .ok_or_else(|| {
                    AmlError::new(
                        AmlErrorKind::AllocationBudgetExhausted,
                        "AML compilation allocation budget exhausted",
                    )
                })?;
            MethodCompiler::new(namespace, scope, bytes, &mut budget.allocation_units).compile()
        }
    }
}

struct MethodCompiler<'namespace, 'budget> {
    namespace: &'namespace AmlNamespace,
    scope: AmlPath,
    bytes: &'namespace [u8],
    cursor: usize,
    instructions: Vec<AmlInstruction>,
    method_names: BTreeSet<AmlPath>,
    break_jumps: Vec<Vec<usize>>,
    allocation_units: &'budget mut usize,
}

impl<'namespace, 'budget> MethodCompiler<'namespace, 'budget> {
    fn new(
        namespace: &'namespace AmlNamespace,
        scope: AmlPath,
        bytes: &'namespace [u8],
        allocation_units: &'budget mut usize,
    ) -> Self {
        Self {
            namespace,
            scope,
            bytes,
            cursor: 0,
            instructions: Vec::new(),
            method_names: BTreeSet::new(),
            break_jumps: Vec::new(),
            allocation_units,
        }
    }

    fn compile(mut self) -> Result<Arc<[AmlInstruction]>, AmlError> {
        self.term_list(self.bytes.len())?;
        Ok(self.instructions.into())
    }

    fn term_list(&mut self, end: usize) -> Result<(), AmlError> {
        while self.cursor < end {
            match self.peek()? {
                0x08 => self.name_op()?,
                0xa3 => self.cursor += 1,
                0xa4 => {
                    self.cursor += 1;
                    self.term_argument()?;
                    self.instructions.push(AmlInstruction::Return);
                }
                0x70 => self.store()?,
                0x75 => self.increment()?,
                0x86 => self.notify()?,
                0xa0 => self.if_op()?,
                0xa2 => self.while_op()?,
                0xa5 => self.break_op()?,
                0x5b => self.extended_statement()?,
                _ => {
                    self.term_argument()?;
                    self.instructions.push(AmlInstruction::Discard);
                }
            }
        }
        if self.cursor == end {
            Ok(())
        } else {
            Err(invalid_vm("AML term crossed its method package boundary"))
        }
    }

    fn name_op(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        let path = self.name_string()?;
        if self.namespace.get(&path).is_some() || !self.method_names.insert(path.clone()) {
            return Err(AmlError::object(
                AmlErrorKind::MalformedEncoding,
                Arc::from(path.as_str()),
                "AML method-local name collides with an existing object",
            ));
        }
        let value = self.data_object()?;
        self.instructions.push(AmlInstruction::Push(value));
        self.instructions.push(AmlInstruction::CreateName(path));
        Ok(())
    }

    fn store(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        self.term_argument()?;
        self.target()
    }

    fn increment(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        match self.byte()? {
            local @ 0x60..=0x67 => {
                self.instructions
                    .push(AmlInstruction::IncrementLocal(local - 0x60));
                Ok(())
            }
            opcode => Err(AmlError::opcode(u16::from(opcode))),
        }
    }

    fn notify(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        let object = self.name_string()?;
        self.term_argument()?;
        self.instructions.push(AmlInstruction::Notify { object });
        Ok(())
    }

    fn if_op(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        let then_end = self.package_end()?;
        self.term_argument()?;
        let false_jump = self.instructions.len();
        self.instructions
            .push(AmlInstruction::JumpIfFalse(usize::MAX));
        self.term_list(then_end)?;
        if self.cursor < self.bytes.len() && self.peek()? == 0xa1 {
            self.cursor += 1;
            let else_end = self.package_end()?;
            let exit_jump = self.instructions.len();
            self.instructions.push(AmlInstruction::Jump(usize::MAX));
            let else_start = self.instructions.len();
            self.patch_jump(false_jump, else_start)?;
            self.term_list(else_end)?;
            let exit = self.instructions.len();
            self.patch_jump(exit_jump, exit)
        } else {
            let exit = self.instructions.len();
            self.patch_jump(false_jump, exit)
        }
    }

    fn while_op(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        let body_end = self.package_end()?;
        let loop_start = self.instructions.len();
        self.term_argument()?;
        let condition_exit = self.instructions.len();
        self.instructions
            .push(AmlInstruction::JumpIfFalse(usize::MAX));
        self.break_jumps.push(Vec::new());
        self.term_list(body_end)?;
        self.instructions.push(AmlInstruction::Jump(loop_start));
        let exit = self.instructions.len();
        self.patch_jump(condition_exit, exit)?;
        let breaks = self
            .break_jumps
            .pop()
            .ok_or_else(|| invalid_vm("AML compiler loop context disappeared"))?;
        for jump in breaks {
            self.patch_jump(jump, exit)?;
        }
        Ok(())
    }

    fn break_op(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        let jump = self.instructions.len();
        self.instructions.push(AmlInstruction::Jump(usize::MAX));
        self.break_jumps
            .last_mut()
            .ok_or_else(|| invalid_vm("AML Break appears outside While"))?
            .push(jump);
        Ok(())
    }

    fn extended_statement(&mut self) -> Result<(), AmlError> {
        self.cursor += 1;
        match self.byte()? {
            0x22 => {
                let ticks = self.literal()?.as_integer()?;
                self.instructions.push(AmlInstruction::Sleep { ticks });
                Ok(())
            }
            0x23 => {
                let mutex = self.name_string()?;
                let timeout_millis = self.u16()?;
                self.instructions.push(AmlInstruction::Acquire {
                    mutex,
                    timeout_millis,
                });
                Ok(())
            }
            0x27 => {
                let mutex = self.name_string()?;
                self.instructions.push(AmlInstruction::Release { mutex });
                Ok(())
            }
            opcode => Err(AmlError::opcode(0x5b00 | u16::from(opcode))),
        }
    }

    fn term_argument(&mut self) -> Result<(), AmlError> {
        match self.peek()? {
            0x00 | 0x01 | 0xff | 0x0a | 0x0b | 0x0c | 0x0e => {
                let value = self.literal()?;
                self.instructions.push(AmlInstruction::Push(value));
                Ok(())
            }
            0x60..=0x67 => {
                let local = self.byte()? - 0x60;
                self.instructions.push(AmlInstruction::LoadLocal(local));
                Ok(())
            }
            0x68..=0x6e => {
                let argument = self.byte()? - 0x68;
                self.instructions
                    .push(AmlInstruction::LoadArgument(argument));
                Ok(())
            }
            0x92 => {
                self.cursor += 1;
                self.term_argument()?;
                self.instructions.push(AmlInstruction::LogicalNot);
                Ok(())
            }
            0x83 => {
                self.cursor += 1;
                let package = self.index_name()?;
                self.instructions
                    .push(AmlInstruction::LoadPackageElement(package));
                Ok(())
            }
            0x90 => {
                self.cursor += 1;
                self.term_argument()?;
                self.term_argument()?;
                self.instructions.push(AmlInstruction::LogicalAnd);
                Ok(())
            }
            0x93 => {
                self.cursor += 1;
                self.term_argument()?;
                self.term_argument()?;
                self.instructions.push(AmlInstruction::Equal);
                Ok(())
            }
            0x95 => {
                self.cursor += 1;
                self.term_argument()?;
                self.term_argument()?;
                self.instructions.push(AmlInstruction::Less);
                Ok(())
            }
            value if is_name_string_start(value) => {
                let path = self.name_string()?;
                if self.method_names.contains(&path) {
                    self.instructions.push(AmlInstruction::LoadName(path));
                    return Ok(());
                }
                match self.namespace.get(&path) {
                    Some(AmlObject::Method(method)) => {
                        for _ in 0..method.argument_count {
                            self.term_argument()?;
                        }
                        self.instructions.push(AmlInstruction::Call {
                            method: path,
                            arguments: method.argument_count,
                        });
                    }
                    Some(_) => self.instructions.push(AmlInstruction::LoadName(path)),
                    None => {
                        return Err(AmlError::object(
                            AmlErrorKind::MissingObject,
                            Arc::from(path.as_str()),
                            "AML term references a missing namespace object",
                        ));
                    }
                }
                Ok(())
            }
            opcode => Err(AmlError::opcode(u16::from(opcode))),
        }
    }

    fn target(&mut self) -> Result<(), AmlError> {
        match self.peek()? {
            0x00 => {
                self.cursor += 1;
                self.instructions.push(AmlInstruction::Discard);
                Ok(())
            }
            0x60..=0x67 => {
                let local = self.byte()? - 0x60;
                self.instructions.push(AmlInstruction::StoreLocal(local));
                Ok(())
            }
            0x5b if self.bytes.get(self.cursor + 1) == Some(&0x31) => {
                self.cursor += 2;
                self.instructions.push(AmlInstruction::Discard);
                Ok(())
            }
            0x88 => {
                let package = self.index_name()?;
                self.instructions
                    .push(AmlInstruction::StorePackageElement(package));
                Ok(())
            }
            value if is_name_string_start(value) => {
                let path = self.name_string()?;
                self.instructions.push(AmlInstruction::StoreName(path));
                Ok(())
            }
            opcode => Err(AmlError::opcode(u16::from(opcode))),
        }
    }

    fn literal(&mut self) -> Result<AmlValue, AmlError> {
        match self.byte()? {
            0x00 => Ok(AmlValue::Integer(0)),
            0x01 => Ok(AmlValue::Integer(1)),
            0xff => Ok(AmlValue::Integer(u64::MAX)),
            0x0a => Ok(AmlValue::Integer(u64::from(self.byte()?))),
            0x0b => Ok(AmlValue::Integer(u64::from(self.u16()?))),
            0x0c => Ok(AmlValue::Integer(u64::from(self.u32()?))),
            0x0e => Ok(AmlValue::Integer(self.u64()?)),
            opcode => Err(AmlError::opcode(u16::from(opcode))),
        }
    }

    fn data_object(&mut self) -> Result<AmlValue, AmlError> {
        match self.peek()? {
            0x00 | 0x01 | 0xff | 0x0a | 0x0b | 0x0c | 0x0e => self.literal(),
            0x12 => self.package_object(),
            opcode => Err(AmlError::opcode(u16::from(opcode))),
        }
    }

    fn package_object(&mut self) -> Result<AmlValue, AmlError> {
        self.cursor += 1;
        let end = self.package_end()?;
        let count = usize::from(self.byte()?);
        self.consume_compiler_allocation(count)?;
        let mut values = Vec::with_capacity(count);
        while values.len() < count && self.cursor < end {
            values.push(self.data_object()?);
        }
        values.resize(count, AmlValue::None);
        if self.cursor != end {
            return Err(invalid_vm("AML package initializer crossed its boundary"));
        }
        Ok(AmlValue::Package(values.into()))
    }

    fn index_name(&mut self) -> Result<AmlPath, AmlError> {
        if self.byte()? != 0x88 {
            return Err(invalid_vm("AML DerefOf requires an Index expression"));
        }
        let package = self.name_string()?;
        self.term_argument()?;
        if self.byte()? != 0x00 {
            return Err(invalid_vm(
                "AML package Index requires a NullName result target",
            ));
        }
        Ok(package)
    }

    fn name_string(&mut self) -> Result<AmlPath, AmlError> {
        let mut base = self.scope.clone();
        let mut upward_search = true;
        if self.peek()? == b'\\' {
            self.cursor += 1;
            base = AmlPath::root();
            upward_search = false;
        } else if self.peek()? == b'^' {
            upward_search = false;
            while self.peek()? == b'^' {
                self.cursor += 1;
                base = base.parent();
            }
        }
        let segment_count = match self.peek()? {
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
        let mut segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            segments.push(self.name_segment()?);
        }
        let candidate = build_path(&base, &segments)?;
        if !upward_search
            || segment_count != 1
            || self.namespace.get(&candidate).is_some()
            || self.method_names.contains(&candidate)
        {
            return Ok(candidate);
        }
        while base != AmlPath::root() {
            base = base.parent();
            let candidate = build_path(&base, &segments)?;
            if self.namespace.get(&candidate).is_some() || self.method_names.contains(&candidate) {
                return Ok(candidate);
            }
        }
        build_path(&self.scope, &segments)
    }

    fn name_segment(&mut self) -> Result<String, AmlError> {
        let bytes = self
            .bytes
            .get(self.cursor..self.cursor + 4)
            .ok_or_else(|| invalid_vm("AML NameSeg is truncated"))?;
        self.cursor += 4;
        let segment =
            core::str::from_utf8(bytes).map_err(|_| invalid_vm("AML NameSeg is not ASCII"))?;
        Ok(String::from(segment))
    }

    fn patch_jump(&mut self, index: usize, target: usize) -> Result<(), AmlError> {
        let instruction = self
            .instructions
            .get_mut(index)
            .ok_or_else(|| invalid_vm("AML compiler jump placeholder is missing"))?;
        match instruction {
            AmlInstruction::Jump(current) | AmlInstruction::JumpIfFalse(current) => {
                *current = target;
                Ok(())
            }
            _ => Err(invalid_vm("AML compiler jump placeholder is invalid")),
        }
    }

    fn package_end(&mut self) -> Result<usize, AmlError> {
        let start = self.cursor;
        let lead = self.byte()?;
        let follow_count = usize::from(lead >> 6);
        let mut length = usize::from(lead & if follow_count == 0 { 0x3f } else { 0x0f });
        for index in 0..follow_count {
            length |= usize::from(self.byte()?) << (4 + index * 8);
        }
        let end = start
            .checked_add(length)
            .ok_or_else(|| invalid_vm("AML package length overflowed"))?;
        if end < self.cursor || end > self.bytes.len() {
            return Err(invalid_vm("AML package extends beyond its method body"));
        }
        Ok(end)
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
            .ok_or_else(|| invalid_vm("unexpected end of AML method"))
    }

    fn u16(&mut self) -> Result<u16, AmlError> {
        Ok(u16::from_le_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, AmlError> {
        Ok(u32::from_le_bytes(self.take::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, AmlError> {
        Ok(u64::from_le_bytes(self.take::<8>()?))
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], AmlError> {
        let bytes = self
            .bytes
            .get(self.cursor..self.cursor + N)
            .ok_or_else(|| invalid_vm("AML integer is truncated"))?;
        self.cursor += N;
        bytes
            .try_into()
            .map_err(|_| invalid_vm("AML integer has invalid width"))
    }

    fn consume_compiler_allocation(&mut self, units: usize) -> Result<(), AmlError> {
        *self.allocation_units = self.allocation_units.checked_sub(units).ok_or_else(|| {
            AmlError::new(
                AmlErrorKind::AllocationBudgetExhausted,
                "AML compilation allocation budget exhausted",
            )
        })?;
        Ok(())
    }
}

fn build_path(base: &AmlPath, segments: &[String]) -> Result<AmlPath, AmlError> {
    let mut path = base.clone();
    for segment in segments {
        path = path.child(segment)?;
    }
    Ok(path)
}

const fn is_name_string_start(value: u8) -> bool {
    matches!(value, b'\\' | b'^' | 0x2e | 0x2f | b'_' | b'A'..=b'Z')
}

fn invalid_vm(detail: &'static str) -> AmlError {
    AmlError::new(AmlErrorKind::MalformedEncoding, detail)
}

fn missing_region(path: &AmlPath) -> AmlError {
    AmlError::object(
        AmlErrorKind::OperationRegion,
        Arc::from(path.as_str()),
        "AML OperationRegion object is missing or has the wrong type",
    )
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

    use super::*;

    fn method_namespace(instructions: Vec<AmlInstruction>) -> (Arc<AmlNamespace>, AmlPath) {
        let method = AmlPath::new(Arc::<str>::from("\\TEST")).unwrap();
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(
                method.clone(),
                AmlObject::Method(AmlMethod::instructions(0, instructions)),
            )
            .unwrap();
        (Arc::new(namespace), method)
    }

    fn path(value: &'static str) -> AmlPath {
        AmlPath::new(Arc::<str>::from(value)).unwrap()
    }

    struct CpuStatusIo {
        selected: AtomicU32,
        control: AtomicU8,
        command: AtomicU8,
        data: AtomicU32,
    }

    impl OperationRegionHandler for CpuStatusIo {
        fn read(
            &self,
            space: OperationRegionSpace,
            base: u64,
            region_length: u64,
            offset: u64,
            width: u8,
        ) -> Result<u64, AmlError> {
            assert_eq!(space, OperationRegionSpace::SystemIo);
            assert_eq!(base, 0x0cd8);
            assert_eq!(region_length, 0x0c);
            match (offset, width) {
                (0, 32) => Ok(u64::from(self.selected.load(Ordering::SeqCst))),
                (4, 8) => Ok(u64::from(self.control.load(Ordering::SeqCst))),
                (5, 8) => Ok(u64::from(self.command.load(Ordering::SeqCst))),
                (8, 32) => Ok(u64::from(self.data.load(Ordering::SeqCst))),
                _ => Err(AmlError::operation_region(
                    "unexpected CPU status OperationRegion read",
                )),
            }
        }

        fn write(
            &self,
            space: OperationRegionSpace,
            base: u64,
            region_length: u64,
            offset: u64,
            width: u8,
            value: u64,
        ) -> Result<(), AmlError> {
            assert_eq!(space, OperationRegionSpace::SystemIo);
            assert_eq!(base, 0x0cd8);
            assert_eq!(region_length, 0x0c);
            match (offset, width) {
                (0, 32) => self.selected.store(
                    u32::try_from(value)
                        .map_err(|_| AmlError::operation_region("CPU selector exceeds u32"))?,
                    Ordering::SeqCst,
                ),
                (4, 8) => self.control.store(
                    u8::try_from(value)
                        .map_err(|_| AmlError::operation_region("CPU control exceeds u8"))?,
                    Ordering::SeqCst,
                ),
                (5, 8) => self.command.store(
                    u8::try_from(value)
                        .map_err(|_| AmlError::operation_region("CPU command exceeds u8"))?,
                    Ordering::SeqCst,
                ),
                (8, 32) => self.data.store(
                    u32::try_from(value)
                        .map_err(|_| AmlError::operation_region("CPU data exceeds u32"))?,
                    Ordering::SeqCst,
                ),
                _ => {
                    return Err(AmlError::operation_region(
                        "unexpected CPU status OperationRegion write",
                    ));
                }
            }
            Ok(())
        }
    }

    fn pres_name(segment: [u8; 4]) -> [u8; 19] {
        [
            b'\\', 0x2f, 0x04, b'_', b'S', b'B', b'_', b'P', b'C', b'I', b'0', b'P', b'R', b'E',
            b'S', segment[0], segment[1], segment[2], segment[3],
        ]
    }

    // Black-box conformance fixtures captured from the ACPI tables emitted by
    // the QEMU 8.2.2 Q35 machine. Only the CTFY/CSCN method bodies are retained
    // as firmware input vectors; the runtime implementation is independent.
    // The producing QEMU source package identifies its project license as GPL-2.0.
    const Q35_CTFY_BODY: &[u8] = &[
        0xa0, 0x0a, 0x93, 0x68, 0x00, 0x86, 0x43, 0x30, 0x30, 0x30, 0x69, 0xa0, 0x0a, 0x93, 0x68,
        0x01, 0x86, 0x43, 0x30, 0x30, 0x31, 0x69, 0xa0, 0x0b, 0x93, 0x68, 0x0a, 0x02, 0x86, 0x43,
        0x30, 0x30, 0x32, 0x69, 0xa0, 0x0b, 0x93, 0x68, 0x0a, 0x03, 0x86, 0x43, 0x30, 0x30, 0x33,
        0x69,
    ];

    const Q35_CSCN_BODY: &[u8] = &[
        0x5b, 0x23, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43, 0x49, 0x30, 0x50, 0x52,
        0x45, 0x53, 0x43, 0x50, 0x4c, 0x4b, 0xff, 0xff, 0x08, 0x43, 0x4e, 0x45, 0x57, 0x12, 0x02,
        0xff, 0x70, 0x00, 0x63, 0x70, 0x01, 0x64, 0xa2, 0x45, 0x12, 0x93, 0x64, 0x01, 0x70, 0x00,
        0x64, 0x70, 0x01, 0x60, 0x70, 0x00, 0x61, 0xa2, 0x4d, 0x0c, 0x90, 0x93, 0x60, 0x01, 0x95,
        0x63, 0x0a, 0x04, 0x70, 0x00, 0x60, 0x70, 0x63, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f,
        0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43, 0x53, 0x45, 0x4c, 0x70, 0x00, 0x5c,
        0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43,
        0x43, 0x4d, 0x44, 0xa0, 0x17, 0x95, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43,
        0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43, 0x44, 0x41, 0x54, 0x63, 0xa5, 0xa0, 0x09, 0x93,
        0x61, 0x0a, 0xff, 0x70, 0x01, 0x64, 0xa5, 0x70, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f,
        0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43, 0x44, 0x41, 0x54, 0x63, 0xa0, 0x24,
        0x93, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45,
        0x53, 0x43, 0x49, 0x4e, 0x53, 0x01, 0x70, 0x63, 0x88, 0x43, 0x4e, 0x45, 0x57, 0x61, 0x00,
        0x75, 0x61, 0x70, 0x01, 0x60, 0xa1, 0x37, 0xa0, 0x35, 0x93, 0x5c, 0x2f, 0x04, 0x5f, 0x53,
        0x42, 0x5f, 0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43, 0x52, 0x4d, 0x56, 0x01,
        0x43, 0x54, 0x46, 0x59, 0x63, 0x0a, 0x03, 0x70, 0x01, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42,
        0x5f, 0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43, 0x52, 0x4d, 0x56, 0x70, 0x01,
        0x60, 0x75, 0x63, 0x70, 0x00, 0x62, 0xa2, 0x45, 0x04, 0x95, 0x62, 0x61, 0x70, 0x83, 0x88,
        0x43, 0x4e, 0x45, 0x57, 0x62, 0x00, 0x63, 0x43, 0x54, 0x46, 0x59, 0x63, 0x01, 0x70, 0x63,
        0x5b, 0x31, 0x70, 0x63, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43, 0x49, 0x30,
        0x50, 0x52, 0x45, 0x53, 0x43, 0x53, 0x45, 0x4c, 0x70, 0x01, 0x5c, 0x2f, 0x04, 0x5f, 0x53,
        0x42, 0x5f, 0x50, 0x43, 0x49, 0x30, 0x50, 0x52, 0x45, 0x53, 0x43, 0x49, 0x4e, 0x53, 0x75,
        0x62, 0x5b, 0x27, 0x5c, 0x2f, 0x04, 0x5f, 0x53, 0x42, 0x5f, 0x50, 0x43, 0x49, 0x30, 0x50,
        0x52, 0x45, 0x53, 0x43, 0x50, 0x4c, 0x4b,
    ];

    struct CpuScanIo {
        selected: AtomicU32,
        event: AtomicU8,
    }

    impl OperationRegionHandler for CpuScanIo {
        fn read(
            &self,
            space: OperationRegionSpace,
            base: u64,
            region_length: u64,
            offset: u64,
            width: u8,
        ) -> Result<u64, AmlError> {
            assert_eq!(space, OperationRegionSpace::SystemIo);
            assert_eq!(base, 0x0cd8);
            assert_eq!(region_length, 0x0c);
            let selected = self.selected.load(Ordering::SeqCst);
            let event = self.event.load(Ordering::SeqCst);
            match (offset, width) {
                (0, 32) => Ok(u64::from(selected)),
                (4, 8) => Ok(if selected <= 2 {
                    match event {
                        1 => 1 << 1,
                        3 => 1 << 2,
                        _ => 0,
                    }
                } else {
                    0
                }),
                (5, 8) => Ok(0),
                (8, 32) => Ok(2),
                _ => Err(AmlError::operation_region(
                    "unexpected CPU scan OperationRegion read",
                )),
            }
        }

        fn write(
            &self,
            space: OperationRegionSpace,
            base: u64,
            region_length: u64,
            offset: u64,
            width: u8,
            value: u64,
        ) -> Result<(), AmlError> {
            assert_eq!(space, OperationRegionSpace::SystemIo);
            assert_eq!(base, 0x0cd8);
            assert_eq!(region_length, 0x0c);
            match (offset, width) {
                (0, 32) => self.selected.store(
                    u32::try_from(value)
                        .map_err(|_| AmlError::operation_region("CPU selector exceeds u32"))?,
                    Ordering::SeqCst,
                ),
                (4, 8) => match value {
                    2 if self.event.load(Ordering::SeqCst) == 1 => {
                        self.event.store(0, Ordering::SeqCst);
                    }
                    4 if self.event.load(Ordering::SeqCst) == 3 => {
                        self.event.store(0, Ordering::SeqCst);
                    }
                    _ => {}
                },
                (5, 8) if value == 0 => {}
                _ => {
                    return Err(AmlError::operation_region(
                        "unexpected CPU scan OperationRegion write",
                    ));
                }
            }
            Ok(())
        }
    }

    #[test]
    fn instruction_budget_exhaustion_is_typed() {
        let (namespace, method) = method_namespace(alloc::vec![AmlInstruction::Jump(0)]);
        let budget = AmlBudget {
            instructions: 2,
            loops: 100,
            recursion: 4,
            allocation_units: 16,
            deadline_tick: 100,
        };
        let mut vm = AmlVm::new(1, namespace, &method, &[], budget).unwrap();
        let error = vm
            .resume(0, &mut VmEnvironment::default(), None)
            .unwrap_err();
        assert_eq!(error.kind, AmlErrorKind::InstructionBudgetExhausted);
    }

    #[test]
    fn bytecode_compilation_reserves_allocation_budget_before_decode() {
        let method = path("\\TEST");
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(
                method.clone(),
                AmlObject::Method(AmlMethod {
                    argument_count: 0,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(&[0xa4, 0x00][..])),
                }),
            )
            .unwrap();
        let budget = AmlBudget {
            instructions: 10,
            loops: 10,
            recursion: 4,
            allocation_units: 0,
            deadline_tick: 100,
        };
        let Err(error) = AmlVm::new(1, Arc::new(namespace), &method, &[], budget) else {
            panic!("zero allocation budget unexpectedly admitted AML compilation");
        };
        assert_eq!(error.kind, AmlErrorKind::AllocationBudgetExhausted);
    }

    #[test]
    fn failed_invocation_releases_its_mutex_authority() {
        let mutex = path("\\LOCK");
        let failing = path("\\FAIL");
        let succeeding = path("\\NEXT");
        let mut namespace = AmlNamespace::default();
        namespace
            .insert(mutex.clone(), AmlObject::Mutex { sync_level: 0 })
            .unwrap();
        namespace
            .insert(
                failing.clone(),
                AmlObject::Method(AmlMethod::instructions(
                    0,
                    alloc::vec![
                        AmlInstruction::Acquire {
                            mutex: mutex.clone(),
                            timeout_millis: 10,
                        },
                        AmlInstruction::LoadName(path("\\MISS")),
                    ],
                )),
            )
            .unwrap();
        namespace
            .insert(
                succeeding.clone(),
                AmlObject::Method(AmlMethod::instructions(
                    0,
                    alloc::vec![
                        AmlInstruction::Acquire {
                            mutex: mutex.clone(),
                            timeout_millis: 10,
                        },
                        AmlInstruction::Release { mutex },
                    ],
                )),
            )
            .unwrap();
        let namespace = Arc::new(namespace);
        let mut environment = VmEnvironment::default();
        let mut vm = AmlVm::new(
            20,
            namespace.clone(),
            &failing,
            &[],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        assert_eq!(
            vm.resume(0, &mut environment, None).unwrap_err().kind,
            AmlErrorKind::MissingObject
        );

        let mut vm = AmlVm::new(
            21,
            namespace,
            &succeeding,
            &[],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        assert_eq!(
            vm.resume(0, &mut environment, None).unwrap(),
            VmProgress::Complete(AmlValue::None)
        );
    }

    #[test]
    fn sleep_yields_without_blocking_executor_cpu() {
        let (namespace, method) = method_namespace(alloc::vec![
            AmlInstruction::Sleep { ticks: 5 },
            AmlInstruction::Push(AmlValue::Integer(7)),
            AmlInstruction::Return,
        ]);
        let mut vm =
            AmlVm::new(1, namespace, &method, &[], AmlBudget::firmware_method(100)).unwrap();
        let mut environment = VmEnvironment::default();
        assert_eq!(
            vm.resume(10, &mut environment, None).unwrap(),
            VmProgress::Waiting(VmWait::Sleep { until_tick: 15 })
        );
        assert_eq!(
            vm.resume(12, &mut environment, None).unwrap(),
            VmProgress::Waiting(VmWait::Sleep { until_tick: 15 })
        );
        assert_eq!(
            vm.resume(15, &mut environment, None).unwrap(),
            VmProgress::Complete(AmlValue::Integer(7))
        );
    }

    #[test]
    fn reduced_q35_cpu_control_methods_access_hotplug_registers() {
        let mut namespace = AmlNamespace::default();
        let region = path("\\_SB_.PCI0.PRES.PRST");
        namespace
            .insert(
                region.clone(),
                AmlObject::OperationRegion(super::super::AmlOperationRegion {
                    space: OperationRegionSpace::SystemIo,
                    offset: 0x0cd8,
                    length: 0x0c,
                }),
            )
            .unwrap();
        for (name, bit_offset, bit_length, access, update_rule) in [
            (
                "\\_SB_.PCI0.PRES.CEJ0",
                35,
                1,
                AmlFieldAccess::Byte,
                AmlFieldUpdateRule::WriteAsZeros,
            ),
            (
                "\\_SB_.PCI0.PRES.CCMD",
                40,
                8,
                AmlFieldAccess::Byte,
                AmlFieldUpdateRule::WriteAsZeros,
            ),
            (
                "\\_SB_.PCI0.PRES.CDAT",
                64,
                32,
                AmlFieldAccess::DWord,
                AmlFieldUpdateRule::Preserve,
            ),
        ] {
            namespace
                .insert(
                    path(name),
                    AmlObject::Field(AmlField {
                        region: path("\\_SB_.PCI0.PRES.PRST"),
                        bit_offset,
                        bit_length,
                        access,
                        lock: false,
                        update_rule,
                    }),
                )
                .unwrap();
        }
        namespace
            .insert(
                path("\\_SB_.PCI0.PRES.CSEL"),
                AmlObject::Field(AmlField {
                    region: region.clone(),
                    bit_offset: 0,
                    bit_length: 32,
                    access: AmlFieldAccess::DWord,
                    lock: false,
                    update_rule: AmlFieldUpdateRule::Preserve,
                }),
            )
            .unwrap();

        let mut cej0 = Vec::new();
        cej0.extend_from_slice(&[0x5b, 0x23]);
        cej0.extend_from_slice(&pres_name(*b"CPLK"));
        cej0.extend_from_slice(&[0xff, 0xff, 0x70, 0x68]);
        cej0.extend_from_slice(&pres_name(*b"CSEL"));
        cej0.extend_from_slice(&[0x70, 0x01]);
        cej0.extend_from_slice(&pres_name(*b"CEJ0"));
        cej0.extend_from_slice(&[0x5b, 0x27]);
        cej0.extend_from_slice(&pres_name(*b"CPLK"));
        namespace
            .insert(
                path("\\_SB_.CPUS.CEJ0"),
                AmlObject::Method(AmlMethod {
                    argument_count: 1,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(cej0.into()),
                }),
            )
            .unwrap();
        namespace
            .insert(
                path("\\_SB_.CPUS.C002._EJ0"),
                AmlObject::Method(AmlMethod {
                    argument_count: 1,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(
                        &[b'C', b'E', b'J', b'0', 0x0a, 0x02][..],
                    )),
                }),
            )
            .unwrap();

        let mut cost = Vec::new();
        cost.extend_from_slice(&[0x5b, 0x23]);
        cost.extend_from_slice(&pres_name(*b"CPLK"));
        cost.extend_from_slice(&[0xff, 0xff, 0x70, 0x68]);
        cost.extend_from_slice(&pres_name(*b"CSEL"));
        cost.extend_from_slice(&[0x70, 0x01]);
        cost.extend_from_slice(&pres_name(*b"CCMD"));
        cost.extend_from_slice(&[0x70, 0x69]);
        cost.extend_from_slice(&pres_name(*b"CDAT"));
        cost.extend_from_slice(&[0x70, 0x0a, 0x02]);
        cost.extend_from_slice(&pres_name(*b"CCMD"));
        cost.extend_from_slice(&[0x70, 0x6a]);
        cost.extend_from_slice(&pres_name(*b"CDAT"));
        cost.extend_from_slice(&[0x5b, 0x27]);
        cost.extend_from_slice(&pres_name(*b"CPLK"));
        namespace
            .insert(
                path("\\_SB_.CPUS.COST"),
                AmlObject::Method(AmlMethod {
                    argument_count: 4,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(cost.into()),
                }),
            )
            .unwrap();
        namespace
            .insert(
                path("\\_SB_.CPUS.C002._OST"),
                AmlObject::Method(AmlMethod {
                    argument_count: 3,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(
                        &[b'C', b'O', b'S', b'T', 0x0a, 0x02, 0x68, 0x69, 0x6a][..],
                    )),
                }),
            )
            .unwrap();
        namespace
            .insert(
                path("\\_SB_.PCI0.PRES.CPEN"),
                AmlObject::Field(AmlField {
                    region,
                    bit_offset: 32,
                    bit_length: 1,
                    access: AmlFieldAccess::Byte,
                    lock: false,
                    update_rule: AmlFieldUpdateRule::WriteAsZeros,
                }),
            )
            .unwrap();
        namespace
            .insert(
                path("\\_SB_.PCI0.PRES.CPLK"),
                AmlObject::Mutex { sync_level: 0 },
            )
            .unwrap();

        // Reduced from the CPU status methods exposed by a Q35 guest. The
        // fixture retains only the ACPI-defined AML ABI needed to exercise
        // namespace lookup, mutex, Field I/O, method calls, and If/Return.
        let csta = Arc::<[u8]>::from(
            &[
                0x5b, 0x23, b'\\', 0x2f, 0x04, b'_', b'S', b'B', b'_', b'P', b'C', b'I', b'0',
                b'P', b'R', b'E', b'S', b'C', b'P', b'L', b'K', 0xff, 0xff, 0x70, 0x68, b'\\',
                0x2f, 0x04, b'_', b'S', b'B', b'_', b'P', b'C', b'I', b'0', b'P', b'R', b'E', b'S',
                b'C', b'S', b'E', b'L', 0x70, 0x00, 0x60, 0xa0, 0x1a, 0x93, b'\\', 0x2f, 0x04,
                b'_', b'S', b'B', b'_', b'P', b'C', b'I', b'0', b'P', b'R', b'E', b'S', b'C', b'P',
                b'E', b'N', 0x01, 0x70, 0x0a, 0x0f, 0x60, 0x5b, 0x27, b'\\', 0x2f, 0x04, b'_',
                b'S', b'B', b'_', b'P', b'C', b'I', b'0', b'P', b'R', b'E', b'S', b'C', b'P', b'L',
                b'K', 0xa4, 0x60,
            ][..],
        );
        namespace
            .insert(
                path("\\_SB_.CPUS.CSTA"),
                AmlObject::Method(AmlMethod {
                    argument_count: 1,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(csta),
                }),
            )
            .unwrap();
        namespace
            .insert(
                path("\\_SB_.CPUS.C002._STA"),
                AmlObject::Method(AmlMethod {
                    argument_count: 0,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(
                        &[0xa4, b'C', b'S', b'T', b'A', 0x0a, 0x02][..],
                    )),
                }),
            )
            .unwrap();

        let namespace = Arc::new(namespace);
        let method = path("\\_SB_.CPUS.C002._STA");
        let io = CpuStatusIo {
            selected: AtomicU32::new(u32::MAX),
            control: AtomicU8::new(1),
            command: AtomicU8::new(0),
            data: AtomicU32::new(0),
        };
        let mut vm = AmlVm::new(
            7,
            namespace.clone(),
            &method,
            &[],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        let result = vm
            .resume(0, &mut VmEnvironment::default(), Some(&io))
            .unwrap();
        assert_eq!(result, VmProgress::Complete(AmlValue::Integer(0x0f)));
        assert_eq!(io.selected.load(Ordering::SeqCst), 2);

        let eject_method = path("\\_SB_.CPUS.C002._EJ0");
        let mut vm = AmlVm::new(
            8,
            namespace.clone(),
            &eject_method,
            &[AmlValue::Integer(1)],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        assert_eq!(
            vm.resume(0, &mut VmEnvironment::default(), Some(&io))
                .unwrap(),
            VmProgress::Complete(AmlValue::None)
        );
        assert_eq!(io.selected.load(Ordering::SeqCst), 2);
        assert_eq!(io.control.load(Ordering::SeqCst), 1 << 3);

        let ost_method = path("\\_SB_.CPUS.C002._OST");
        let mut vm = AmlVm::new(
            9,
            namespace,
            &ost_method,
            &[
                AmlValue::Integer(3),
                AmlValue::Integer(4),
                AmlValue::Buffer(Arc::from([])),
            ],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        assert_eq!(
            vm.resume(0, &mut VmEnvironment::default(), Some(&io))
                .unwrap(),
            VmProgress::Complete(AmlValue::None)
        );
        assert_eq!(io.selected.load(Ordering::SeqCst), 2);
        assert_eq!(io.command.load(Ordering::SeqCst), 2);
        assert_eq!(io.data.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn q35_gpe_scan_yields_typed_insert_and_remove_notifications() {
        let mut namespace = AmlNamespace::default();
        let region = path("\\_SB_.PCI0.PRES.PRST");
        namespace
            .insert(
                region.clone(),
                AmlObject::OperationRegion(super::super::AmlOperationRegion {
                    space: OperationRegionSpace::SystemIo,
                    offset: 0x0cd8,
                    length: 0x0c,
                }),
            )
            .unwrap();
        for (name, bit_offset, bit_length, access, update_rule) in [
            (
                "\\_SB_.PCI0.PRES.CSEL",
                0,
                32,
                AmlFieldAccess::DWord,
                AmlFieldUpdateRule::Preserve,
            ),
            (
                "\\_SB_.PCI0.PRES.CINS",
                33,
                1,
                AmlFieldAccess::Byte,
                AmlFieldUpdateRule::WriteAsZeros,
            ),
            (
                "\\_SB_.PCI0.PRES.CRMV",
                34,
                1,
                AmlFieldAccess::Byte,
                AmlFieldUpdateRule::WriteAsZeros,
            ),
            (
                "\\_SB_.PCI0.PRES.CCMD",
                40,
                8,
                AmlFieldAccess::Byte,
                AmlFieldUpdateRule::WriteAsZeros,
            ),
            (
                "\\_SB_.PCI0.PRES.CDAT",
                64,
                32,
                AmlFieldAccess::DWord,
                AmlFieldUpdateRule::Preserve,
            ),
        ] {
            namespace
                .insert(
                    path(name),
                    AmlObject::Field(AmlField {
                        region: region.clone(),
                        bit_offset,
                        bit_length,
                        access,
                        lock: false,
                        update_rule,
                    }),
                )
                .unwrap();
        }
        namespace
            .insert(
                path("\\_SB_.PCI0.PRES.CPLK"),
                AmlObject::Mutex { sync_level: 0 },
            )
            .unwrap();
        for slot in 0..4u8 {
            namespace
                .insert(
                    path(match slot {
                        0 => "\\_SB_.CPUS.C000",
                        1 => "\\_SB_.CPUS.C001",
                        2 => "\\_SB_.CPUS.C002",
                        _ => "\\_SB_.CPUS.C003",
                    }),
                    AmlObject::Processor(super::super::AmlProcessor {
                        processor_id: slot,
                        pblk_address: 0,
                        pblk_length: 0,
                    }),
                )
                .unwrap();
        }
        namespace
            .insert(
                path("\\_SB_.CPUS.CTFY"),
                AmlObject::Method(AmlMethod {
                    argument_count: 2,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(Q35_CTFY_BODY)),
                }),
            )
            .unwrap();
        namespace
            .insert(
                path("\\_SB_.CPUS.CSCN"),
                AmlObject::Method(AmlMethod {
                    argument_count: 0,
                    serialized: true,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(Q35_CSCN_BODY)),
                }),
            )
            .unwrap();
        let gpe_method = path("\\_GPE._E02");
        namespace
            .insert(
                gpe_method.clone(),
                AmlObject::Method(AmlMethod {
                    argument_count: 0,
                    serialized: false,
                    sync_level: 0,
                    body: AmlMethodBody::Bytecode(Arc::from(
                        &[
                            b'\\', 0x2f, 0x03, b'_', b'S', b'B', b'_', b'C', b'P', b'U', b'S',
                            b'C', b'S', b'C', b'N',
                        ][..],
                    )),
                }),
            )
            .unwrap();
        let namespace = Arc::new(namespace);
        let io = CpuScanIo {
            selected: AtomicU32::new(0),
            event: AtomicU8::new(1),
        };
        let mut environment = VmEnvironment::default();

        let mut vm = AmlVm::new(
            10,
            namespace.clone(),
            &gpe_method,
            &[],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        assert_eq!(
            vm.resume(0, &mut environment, Some(&io)).unwrap(),
            VmProgress::Notify {
                object: path("\\_SB_.CPUS.C002"),
                value: 1,
            }
        );
        assert_eq!(
            vm.resume(0, &mut environment, Some(&io)).unwrap(),
            VmProgress::Complete(AmlValue::None)
        );
        assert_eq!(io.event.load(Ordering::SeqCst), 0);

        io.event.store(3, Ordering::SeqCst);
        io.selected.store(0, Ordering::SeqCst);
        let mut vm = AmlVm::new(
            11,
            namespace,
            &gpe_method,
            &[],
            AmlBudget::firmware_method(100),
        )
        .unwrap();
        assert_eq!(
            vm.resume(0, &mut environment, Some(&io)).unwrap(),
            VmProgress::Notify {
                object: path("\\_SB_.CPUS.C002"),
                value: 3,
            }
        );
        assert_eq!(
            vm.resume(0, &mut environment, Some(&io)).unwrap(),
            VmProgress::Complete(AmlValue::None)
        );
        assert_eq!(io.event.load(Ordering::SeqCst), 0);
    }
}
