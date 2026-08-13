use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{AmlError, AmlErrorKind};

use super::{
    AmlMethod, AmlMethodBody, AmlNamespace, AmlObject, AmlPath, AmlValue, OperationRegionSpace,
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
    LoadName(AmlPath),
    Equal,
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
        timeout_tick: u64,
    },
    Release {
        mutex: AmlPath,
    },
    Notify {
        object: AmlPath,
        value: u64,
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
    mutex_owners: BTreeMap<AmlPath, u64>,
}

impl VmEnvironment {
    fn acquire(&mut self, path: &AmlPath, owner: u64) -> bool {
        match self.mutex_owners.get(path).copied() {
            None => {
                self.mutex_owners.insert(path.clone(), owner);
                true
            }
            Some(current) if current == owner => true,
            Some(_) => false,
        }
    }

    fn release(&mut self, path: &AmlPath, owner: u64) -> Result<(), AmlError> {
        if self.mutex_owners.get(path).copied() != Some(owner) {
            return Err(AmlError::object(
                AmlErrorKind::Mutex,
                Arc::from(path.as_str()),
                "AML method attempted to release a mutex it does not own",
            ));
        }
        self.mutex_owners.remove(path);
        Ok(())
    }
}

struct Frame {
    instructions: Arc<[AmlInstruction]>,
    pc: usize,
    arguments: [AmlValue; 7],
    locals: [AmlValue; 8],
}

impl Frame {
    fn new(instructions: Arc<[AmlInstruction]>, arguments: &[AmlValue]) -> Self {
        let mut frame = Self {
            instructions,
            pc: 0,
            arguments: core::array::from_fn(|_| AmlValue::None),
            locals: core::array::from_fn(|_| AmlValue::None),
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
        let method = namespace.method(method)?;
        if arguments.len() != usize::from(method.argument_count) {
            return Err(AmlError::new(
                AmlErrorKind::InvalidObjectType,
                "AML method argument count does not match declaration",
            ));
        }
        let instructions = compile_method(method)?;
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
                _ => self.waiting = None,
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
                AmlInstruction::LoadName(path) => self.values.push(self.namespace.value(&path)?),
                AmlInstruction::Equal => {
                    let right = self.pop_value()?;
                    let left = self.pop_value()?;
                    self.values
                        .push(AmlValue::Integer(u64::from(left == right)));
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
                    let method = self.namespace.method(&method)?;
                    if method.argument_count != arguments {
                        return Err(invalid_vm("AML call argument count does not match method"));
                    }
                    self.frames
                        .push(Frame::new(compile_method(method)?, &call_arguments));
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
                    timeout_tick,
                } => {
                    if !environment.acquire(&mutex, self.id) {
                        let frame = self
                            .frames
                            .last_mut()
                            .ok_or_else(|| invalid_vm("AML mutex has no call frame"))?;
                        frame.pc = frame.pc.saturating_sub(1);
                        let waiting = VmWait::Mutex {
                            path: mutex,
                            timeout_tick,
                        };
                        self.waiting = Some(waiting.clone());
                        return Ok(VmProgress::Waiting(waiting));
                    }
                }
                AmlInstruction::Release { mutex } => environment.release(&mutex, self.id)?,
                AmlInstruction::Notify { object, value } => {
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

    fn jump(&mut self, target: usize) -> Result<(), AmlError> {
        let frame = self
            .frames
            .last_mut()
            .ok_or_else(|| invalid_vm("AML jump has no call frame"))?;
        if target >= frame.instructions.len() {
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

fn compile_method(method: &AmlMethod) -> Result<Arc<[AmlInstruction]>, AmlError> {
    match &method.body {
        AmlMethodBody::Instructions(instructions) => Ok(instructions.clone()),
        AmlMethodBody::Bytecode(bytes) => compile_bytecode(bytes),
    }
}

fn compile_bytecode(bytes: &[u8]) -> Result<Arc<[AmlInstruction]>, AmlError> {
    let mut cursor = 0usize;
    let mut instructions = Vec::new();
    while cursor < bytes.len() {
        match bytes[cursor] {
            0xa3 => cursor += 1,
            0xa4 => {
                cursor += 1;
                let (value, consumed) = literal(&bytes[cursor..])?;
                cursor += consumed;
                instructions.push(AmlInstruction::Push(value));
                instructions.push(AmlInstruction::Return);
            }
            0x5b if bytes.get(cursor + 1) == Some(&0x22) => {
                cursor += 2;
                let (value, consumed) = literal(&bytes[cursor..])?;
                cursor += consumed;
                instructions.push(AmlInstruction::Sleep {
                    ticks: value.as_integer()?,
                });
            }
            opcode => return Err(AmlError::opcode(u16::from(opcode))),
        }
    }
    Ok(instructions.into())
}

fn literal(bytes: &[u8]) -> Result<(AmlValue, usize), AmlError> {
    match bytes.first().copied() {
        Some(0x00) => Ok((AmlValue::Integer(0), 1)),
        Some(0x01) => Ok((AmlValue::Integer(1), 1)),
        Some(0xff) => Ok((AmlValue::Integer(u64::MAX), 1)),
        Some(0x0a) if bytes.len() >= 2 => Ok((AmlValue::Integer(u64::from(bytes[1])), 2)),
        Some(0x0b) if bytes.len() >= 3 => Ok((
            AmlValue::Integer(u64::from(u16::from_le_bytes([bytes[1], bytes[2]]))),
            3,
        )),
        Some(0x0c) if bytes.len() >= 5 => Ok((
            AmlValue::Integer(u64::from(u32::from_le_bytes(
                bytes[1..5]
                    .try_into()
                    .map_err(|_| invalid_vm("AML dword literal is truncated"))?,
            ))),
            5,
        )),
        Some(opcode) => Err(AmlError::opcode(u16::from(opcode))),
        None => Err(invalid_vm("AML literal is missing")),
    }
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
}
