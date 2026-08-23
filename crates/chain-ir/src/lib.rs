#![forbid(unsafe_code)]

//! Versioned, deterministic Chain IR representation.

use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
use core::fmt;
use std::error::Error;

const CHAIN_IR_PROGRAM_TYPE_ID: u16 = 0xA001;
const CHAIN_IR_INSTRUCTION_TYPE_ID: u16 = 0xA002;
const CHAIN_IR_REGISTER_LIST_TYPE_ID: u16 = 0xA003;
const ENCODING_VERSION: u16 = 1;

/// Current supported Chain IR version.
pub const CURRENT_CHAIN_IR_VERSION: u16 = 1;
/// Maximum number of instructions allowed in one IR program.
pub const MAX_INSTRUCTIONS: usize = 4_096;
/// Maximum number of register operands in a single system call.
pub const MAX_SYSTEM_CALL_ARGS: usize = 16;
/// Maximum UTF-8 byte length of a system call target name.
pub const MAX_SYSTEM_CALL_NAME_BYTES: usize = 128;

/// Errors produced by Chain IR helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainIrError {
    /// IR version is not supported.
    UnsupportedVersion(u16),
    /// Program contains no instructions.
    EmptyProgram,
    /// Program exceeds the maximum instruction count.
    TooManyInstructions(usize),
    /// A canonical field identifier overflowed `u16`.
    FieldIdOverflow(usize),
    /// A system call target name was empty.
    EmptySystemCall,
    /// A system call target name exceeds the supported length.
    SystemCallNameTooLong(usize),
    /// A system call carries too many register arguments.
    TooManySystemCallArgs(usize),
    /// Canonical encoding failed.
    CanonicalEncoding(CanonicalEncodingError),
}

impl fmt::Display for ChainIrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported chain ir version: {version}")
            }
            Self::EmptyProgram => {
                write!(f, "chain ir program must contain at least one instruction")
            }
            Self::TooManyInstructions(count) => write!(
                f,
                "chain ir program has {count} instructions, maximum is {MAX_INSTRUCTIONS}"
            ),
            Self::FieldIdOverflow(index) => {
                write!(f, "canonical field id overflow at index {index}")
            }
            Self::EmptySystemCall => write!(f, "system call target must not be empty"),
            Self::SystemCallNameTooLong(size) => write!(
                f,
                "system call target is {size} bytes, maximum is {MAX_SYSTEM_CALL_NAME_BYTES}"
            ),
            Self::TooManySystemCallArgs(count) => write!(
                f,
                "system call has {count} args, maximum is {MAX_SYSTEM_CALL_ARGS}"
            ),
            Self::CanonicalEncoding(error) => error.fmt(f),
        }
    }
}

impl Error for ChainIrError {}

impl From<CanonicalEncodingError> for ChainIrError {
    fn from(value: CanonicalEncodingError) -> Self {
        Self::CanonicalEncoding(value)
    }
}

/// Deterministic Chain IR instruction set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrInstruction {
    /// Loads an input object reference into a register.
    LoadObject { dst: u16, input_index: u16 },
    /// Reads a field from an object into a register.
    ReadField {
        dst: u16,
        object: u16,
        field_index: u16,
    },
    /// Writes a register value into an object field.
    WriteField {
        object: u16,
        field_index: u16,
        value: u16,
    },
    /// Adds two u64 registers and stores the result.
    AddU64 { dst: u16, lhs: u16, rhs: u16 },
    /// Calls a governance-installed deterministic system module entrypoint.
    CallSystem {
        target: String,
        args: Vec<u16>,
        result: Option<u16>,
    },
    /// Creates a new object from register operands.
    CreateObject {
        data: u16,
        type_hash: u16,
        owner: u16,
    },
    /// Marks an input object as consumed.
    ConsumeObject { object: u16 },
    /// Emits an event with type and payload registers.
    EmitEvent { type_tag: u16, data: u16 },
}

impl IrInstruction {
    const fn opcode(&self) -> u16 {
        match self {
            Self::LoadObject { .. } => 1,
            Self::ReadField { .. } => 2,
            Self::WriteField { .. } => 3,
            Self::AddU64 { .. } => 4,
            Self::CallSystem { .. } => 5,
            Self::CreateObject { .. } => 6,
            Self::ConsumeObject { .. } => 7,
            Self::EmitEvent { .. } => 8,
        }
    }

    fn validate(&self) -> Result<(), ChainIrError> {
        if let Self::CallSystem { target, args, .. } = self {
            if target.is_empty() {
                return Err(ChainIrError::EmptySystemCall);
            }
            if target.len() > MAX_SYSTEM_CALL_NAME_BYTES {
                return Err(ChainIrError::SystemCallNameTooLong(target.len()));
            }
            if args.len() > MAX_SYSTEM_CALL_ARGS {
                return Err(ChainIrError::TooManySystemCallArgs(args.len()));
            }
        }
        Ok(())
    }
}

/// A versioned, statically inspectable Chain IR program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainIrProgram {
    /// Chain IR dialect version.
    pub ir_version: u16,
    /// Program instructions in deterministic execution order.
    pub instructions: Vec<IrInstruction>,
}

impl ChainIrProgram {
    /// Validates program structure and bounds.
    pub fn validate(&self) -> Result<(), ChainIrError> {
        if self.ir_version != CURRENT_CHAIN_IR_VERSION {
            return Err(ChainIrError::UnsupportedVersion(self.ir_version));
        }
        if self.instructions.is_empty() {
            return Err(ChainIrError::EmptyProgram);
        }
        if self.instructions.len() > MAX_INSTRUCTIONS {
            return Err(ChainIrError::TooManyInstructions(self.instructions.len()));
        }
        for instruction in &self.instructions {
            instruction.validate()?;
        }
        Ok(())
    }
}

/// Statically inspectable summary data for a Chain IR program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramSummary {
    /// Number of instructions in the program.
    pub instruction_count: usize,
    /// Maximum register index referenced by any instruction.
    pub max_register: Option<u16>,
    /// Number of system module calls in the program.
    pub system_call_count: usize,
    /// Whether the program can create objects.
    pub creates_objects: bool,
    /// Whether the program can consume objects.
    pub consumes_objects: bool,
    /// Whether the program can emit events.
    pub emits_events: bool,
}

/// Returns static summary information for a validated program.
pub fn summarize_program(program: &ChainIrProgram) -> Result<ProgramSummary, ChainIrError> {
    program.validate()?;

    let mut max_register: Option<u16> = None;
    let mut system_call_count = 0usize;
    let mut creates_objects = false;
    let mut consumes_objects = false;
    let mut emits_events = false;

    let mut observe = |reg: u16| {
        max_register = Some(max_register.map_or(reg, |current| current.max(reg)));
    };

    for instruction in &program.instructions {
        match instruction {
            IrInstruction::LoadObject { dst, input_index } => {
                observe(*dst);
                let _ = input_index;
            }
            IrInstruction::ReadField {
                dst,
                object,
                field_index,
            } => {
                observe(*dst);
                observe(*object);
                let _ = field_index;
            }
            IrInstruction::WriteField {
                object,
                field_index,
                value,
            } => {
                observe(*object);
                observe(*value);
                let _ = field_index;
            }
            IrInstruction::AddU64 { dst, lhs, rhs } => {
                observe(*dst);
                observe(*lhs);
                observe(*rhs);
            }
            IrInstruction::CallSystem { args, result, .. } => {
                system_call_count += 1;
                for &arg in args {
                    observe(arg);
                }
                if let Some(result) = result {
                    observe(*result);
                }
            }
            IrInstruction::CreateObject {
                data,
                type_hash,
                owner,
            } => {
                creates_objects = true;
                observe(*data);
                observe(*type_hash);
                observe(*owner);
            }
            IrInstruction::ConsumeObject { object } => {
                consumes_objects = true;
                observe(*object);
            }
            IrInstruction::EmitEvent { type_tag, data } => {
                emits_events = true;
                observe(*type_tag);
                observe(*data);
            }
        }
    }

    Ok(ProgramSummary {
        instruction_count: program.instructions.len(),
        max_register,
        system_call_count,
        creates_objects,
        consumes_objects,
        emits_events,
    })
}

/// Encodes a full Chain IR program using canonical framed encoding.
pub fn encode_chain_ir_program(program: &ChainIrProgram) -> Result<Vec<u8>, ChainIrError> {
    program.validate()?;

    let mut canonical = CanonicalStruct::new(CHAIN_IR_PROGRAM_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, program.ir_version)?;
    canonical.field_u32(2, program.instructions.len() as u32)?;

    for (index, instruction) in program.instructions.iter().enumerate() {
        let field_id =
            u16::try_from(3 + index).map_err(|_| ChainIrError::FieldIdOverflow(index))?;
        canonical.field_bytes(field_id, encode_instruction(instruction)?)?;
    }

    Ok(canonical.finish()?)
}

/// Encodes one Chain IR instruction in canonical framed form.
pub fn encode_instruction(instruction: &IrInstruction) -> Result<Vec<u8>, ChainIrError> {
    instruction.validate()?;

    let mut canonical = CanonicalStruct::new(CHAIN_IR_INSTRUCTION_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, instruction.opcode())?;

    match instruction {
        IrInstruction::LoadObject { dst, input_index } => {
            canonical.field_u16(2, *dst)?;
            canonical.field_u16(3, *input_index)?;
        }
        IrInstruction::ReadField {
            dst,
            object,
            field_index,
        } => {
            canonical.field_u16(2, *dst)?;
            canonical.field_u16(3, *object)?;
            canonical.field_u16(4, *field_index)?;
        }
        IrInstruction::WriteField {
            object,
            field_index,
            value,
        } => {
            canonical.field_u16(2, *object)?;
            canonical.field_u16(3, *field_index)?;
            canonical.field_u16(4, *value)?;
        }
        IrInstruction::AddU64 { dst, lhs, rhs } => {
            canonical.field_u16(2, *dst)?;
            canonical.field_u16(3, *lhs)?;
            canonical.field_u16(4, *rhs)?;
        }
        IrInstruction::CallSystem {
            target,
            args,
            result,
        } => {
            canonical.field_str(2, target)?;
            canonical.field_bytes(3, encode_register_list(args)?)?;
            if let Some(result) = result {
                canonical.field_u16(4, *result)?;
            }
        }
        IrInstruction::CreateObject {
            data,
            type_hash,
            owner,
        } => {
            canonical.field_u16(2, *data)?;
            canonical.field_u16(3, *type_hash)?;
            canonical.field_u16(4, *owner)?;
        }
        IrInstruction::ConsumeObject { object } => {
            canonical.field_u16(2, *object)?;
        }
        IrInstruction::EmitEvent { type_tag, data } => {
            canonical.field_u16(2, *type_tag)?;
            canonical.field_u16(3, *data)?;
        }
    }

    Ok(canonical.finish()?)
}

fn encode_register_list(args: &[u16]) -> Result<Vec<u8>, ChainIrError> {
    if args.len() > MAX_SYSTEM_CALL_ARGS {
        return Err(ChainIrError::TooManySystemCallArgs(args.len()));
    }

    let mut canonical = CanonicalStruct::new(CHAIN_IR_REGISTER_LIST_TYPE_ID, ENCODING_VERSION);
    canonical.field_u16(1, args.len() as u16)?;
    for (index, value) in args.iter().enumerate() {
        let field_id =
            u16::try_from(2 + index).map_err(|_| ChainIrError::FieldIdOverflow(index))?;
        canonical.field_u16(field_id, *value)?;
    }

    Ok(canonical.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_program() -> ChainIrProgram {
        ChainIrProgram {
            ir_version: CURRENT_CHAIN_IR_VERSION,
            instructions: vec![
                IrInstruction::LoadObject {
                    dst: 0,
                    input_index: 0,
                },
                IrInstruction::ReadField {
                    dst: 1,
                    object: 0,
                    field_index: 0,
                },
                IrInstruction::AddU64 {
                    dst: 2,
                    lhs: 1,
                    rhs: 1,
                },
                IrInstruction::WriteField {
                    object: 0,
                    field_index: 0,
                    value: 2,
                },
                IrInstruction::CreateObject {
                    data: 2,
                    type_hash: 3,
                    owner: 4,
                },
                IrInstruction::EmitEvent {
                    type_tag: 5,
                    data: 2,
                },
                IrInstruction::CallSystem {
                    target: "system.transfer".to_string(),
                    args: vec![0, 2],
                    result: Some(6),
                },
                IrInstruction::ConsumeObject { object: 0 },
            ],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn program_encoding_is_deterministic() {
        let program = sample_program();
        let left = encode_chain_ir_program(&program).unwrap();
        let right = encode_chain_ir_program(&program).unwrap();
        assert_eq!(left, right);
        assert!(!left.is_empty());
    }

    #[test]
    fn unsupported_ir_version_is_rejected() {
        let mut program = sample_program();
        program.ir_version = 2;
        assert_eq!(
            encode_chain_ir_program(&program),
            Err(ChainIrError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn too_many_instructions_is_rejected() {
        let instructions = vec![IrInstruction::ConsumeObject { object: 0 }; MAX_INSTRUCTIONS + 1];
        let program = ChainIrProgram {
            ir_version: CURRENT_CHAIN_IR_VERSION,
            instructions,
        };
        assert_eq!(
            encode_chain_ir_program(&program),
            Err(ChainIrError::TooManyInstructions(MAX_INSTRUCTIONS + 1))
        );
    }

    #[test]
    fn empty_system_call_target_is_rejected() {
        let mut program = sample_program();
        program.instructions.push(IrInstruction::CallSystem {
            target: String::new(),
            args: vec![],
            result: None,
        });
        assert_eq!(
            encode_chain_ir_program(&program),
            Err(ChainIrError::EmptySystemCall)
        );
    }

    #[test]
    fn summary_reports_static_shape() {
        let summary = summarize_program(&sample_program()).unwrap();
        assert_eq!(summary.instruction_count, 8);
        assert_eq!(summary.max_register, Some(6));
        assert_eq!(summary.system_call_count, 1);
        assert!(summary.creates_objects);
        assert!(summary.consumes_objects);
        assert!(summary.emits_events);
    }

    #[test]
    fn chain_ir_stable_encoding_vector() {
        let encoded = encode_chain_ir_program(&sample_program()).unwrap();
        assert_eq!(
            hex(&encoded),
            "534e524501a001000a00010002000000010002000400000008000000030022000000534e524502a00100030001000200000001000200020000000000030002000000000004002a000000534e524502a001000400010002000000020002000200000001000300020000000000040002000000000005002a000000534e524502a001000400010002000000040002000200000002000300020000000100040002000000010006002a000000534e524502a001000400010002000000030002000200000000000300020000000000040002000000020007002a000000534e524502a0010004000100020000000600020002000000020003000200000003000400020000000400080022000000534e524502a001000300010002000000080002000200000005000300020000000200090057000000534e524502a001000400010002000000050002000f00000073797374656d2e7472616e73666572030022000000534e524503a00100030001000200000002000200020000000000030002000000020004000200000006000a001a000000534e524502a00100020001000200000007000200020000000000"
        );
    }
}
