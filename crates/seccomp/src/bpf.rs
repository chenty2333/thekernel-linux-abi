use alloc::{boxed::Box, vec::Vec};

use crate::{
    BPF_A, BPF_ABS, BPF_ADD, BPF_ALU, BPF_AND, BPF_CLASS_MASK, BPF_DIV, BPF_IMM, BPF_JA, BPF_JEQ,
    BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_LDX, BPF_LEN, BPF_LSH, BPF_MAXINSNS,
    BPF_MEM, BPF_MEMWORDS, BPF_MISC, BPF_MUL, BPF_NEG, BPF_OP_MASK, BPF_OR, BPF_RET, BPF_RSH,
    BPF_RVAL_MASK, BPF_SRC_MASK, BPF_ST, BPF_STX, BPF_SUB, BPF_TAX, BPF_TXA, BPF_W, BPF_X, BPF_XOR,
    SECCOMP_DATA_SIZE, SECCOMP_RET_KILL_PROCESS,
};

/// Linux `struct sock_filter`, the eight-byte classic-BPF instruction format.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
#[repr(C)]
pub struct ClassicBpfInstruction {
    /// Encoded class, operation, source, size, and addressing mode.
    pub code: u16,
    /// Relative forward offset when a conditional branch is true.
    pub jump_true: u8,
    /// Relative forward offset when a conditional branch is false.
    pub jump_false: u8,
    /// Immediate, absolute byte offset, scratch index, or jump distance.
    pub value: u32,
}

impl ClassicBpfInstruction {
    /// Creates one instruction from its Linux UAPI fields.
    pub const fn new(code: u16, jump_true: u8, jump_false: u8, value: u32) -> Self {
        Self {
            code,
            jump_true,
            jump_false,
            value,
        }
    }
}

/// Immutable syscall facts visible to a seccomp filter.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct SeccompData {
    /// Original Linux syscall number.
    pub number: i32,
    /// Linux audit architecture value.
    pub architecture: u32,
    /// Userspace instruction pointer after the syscall instruction.
    pub instruction_pointer: u64,
    /// Six original syscall argument registers.
    pub arguments: [u64; 6],
}

impl SeccompData {
    fn load_word(&self, offset: usize) -> Option<u32> {
        if offset & 3 != 0 || offset >= SECCOMP_DATA_SIZE {
            return None;
        }
        match offset {
            0 => Some(self.number as u32),
            4 => Some(self.architecture),
            8 | 12 => Some(native_u64_word(self.instruction_pointer, offset - 8)),
            16..=60 => {
                let relative = offset - 16;
                let argument = relative / 8;
                Some(native_u64_word(self.arguments[argument], relative & 7))
            }
            _ => None,
        }
    }
}

#[cfg(target_endian = "little")]
const fn native_u64_word(value: u64, byte_offset: usize) -> u32 {
    if byte_offset == 0 {
        value as u32
    } else {
        (value >> 32) as u32
    }
}

#[cfg(target_endian = "big")]
const fn native_u64_word(value: u64, byte_offset: usize) -> u32 {
    if byte_offset == 0 {
        (value >> 32) as u32
    } else {
        value as u32
    }
}

/// Rejection reason produced while validating an untrusted cBPF program.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProgramError {
    /// The program contains no instructions.
    Empty,
    /// The program exceeds Linux's 4096-instruction limit.
    TooLong,
    /// Allocation for validation metadata failed.
    NoMemory,
    /// An opcode is not in Linux's seccomp cBPF subset.
    InvalidOpcode {
        /// Instruction index.
        program_counter: usize,
        /// Rejected encoded opcode.
        code: u16,
    },
    /// An immediate division operand is zero.
    DivisionByZero {
        /// Instruction index.
        program_counter: usize,
    },
    /// An immediate shift is at least 32 bits.
    ShiftOutOfRange {
        /// Instruction index.
        program_counter: usize,
    },
    /// A scratch-memory index is outside the 16-word array.
    ScratchOutOfRange {
        /// Instruction index.
        program_counter: usize,
    },
    /// A branch does not land on a later instruction in the program.
    JumpOutOfRange {
        /// Instruction index.
        program_counter: usize,
    },
    /// A seccomp-data load is not 32-bit aligned.
    DataOffsetUnaligned {
        /// Instruction index.
        program_counter: usize,
    },
    /// A seccomp-data load is outside the 64-byte input object.
    DataOffsetOutOfRange {
        /// Instruction index.
        program_counter: usize,
    },
    /// A reachable path reads a scratch word before storing it.
    UninitializedScratch {
        /// Instruction index.
        program_counter: usize,
    },
    /// The final instruction is not `RET K` or `RET A`.
    MissingReturn,
}

/// A verified immutable seccomp classic-BPF program.
pub struct VerifiedProgram {
    instructions: Box<[ClassicBpfInstruction]>,
}

impl VerifiedProgram {
    /// Validates and takes ownership of a complete userspace copy.
    pub fn try_from_vec(instructions: Vec<ClassicBpfInstruction>) -> Result<Self, ProgramError> {
        verify_program(&instructions)?;
        Ok(Self {
            instructions: instructions.into_boxed_slice(),
        })
    }

    /// Fallibly copies and validates a program.
    pub fn try_copy_from_slice(
        instructions: &[ClassicBpfInstruction],
    ) -> Result<Self, ProgramError> {
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(instructions.len())
            .map_err(|_| ProgramError::NoMemory)?;
        copied.extend_from_slice(instructions);
        Self::try_from_vec(copied)
    }

    /// Returns the classic-BPF instruction count.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns whether this program is empty. Verified programs are never
    /// empty; this method is provided alongside [`Self::len`].
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Evaluates the program without allocation or unbounded control flow.
    pub fn evaluate(&self, data: &SeccompData) -> u32 {
        run_verified(&self.instructions, data)
    }
}

fn allowed_opcode(code: u16) -> bool {
    matches!(
        code,
        x if x == BPF_LD | BPF_W | BPF_ABS
            || x == BPF_LD | BPF_W | BPF_LEN
            || x == BPF_LDX | BPF_W | BPF_LEN
            || x == BPF_RET | BPF_K
            || x == BPF_RET | BPF_A
            || x == BPF_ALU | BPF_ADD | BPF_K
            || x == BPF_ALU | BPF_ADD | BPF_X
            || x == BPF_ALU | BPF_SUB | BPF_K
            || x == BPF_ALU | BPF_SUB | BPF_X
            || x == BPF_ALU | BPF_MUL | BPF_K
            || x == BPF_ALU | BPF_MUL | BPF_X
            || x == BPF_ALU | BPF_DIV | BPF_K
            || x == BPF_ALU | BPF_DIV | BPF_X
            || x == BPF_ALU | BPF_AND | BPF_K
            || x == BPF_ALU | BPF_AND | BPF_X
            || x == BPF_ALU | BPF_OR | BPF_K
            || x == BPF_ALU | BPF_OR | BPF_X
            || x == BPF_ALU | BPF_XOR | BPF_K
            || x == BPF_ALU | BPF_XOR | BPF_X
            || x == BPF_ALU | BPF_LSH | BPF_K
            || x == BPF_ALU | BPF_LSH | BPF_X
            || x == BPF_ALU | BPF_RSH | BPF_K
            || x == BPF_ALU | BPF_RSH | BPF_X
            || x == BPF_ALU | BPF_NEG
            || x == BPF_LD | BPF_IMM
            || x == BPF_LDX | BPF_IMM
            || x == BPF_MISC | BPF_TAX
            || x == BPF_MISC | BPF_TXA
            || x == BPF_LD | BPF_MEM
            || x == BPF_LDX | BPF_MEM
            || x == BPF_ST
            || x == BPF_STX
            || x == BPF_JMP | BPF_JA
            || x == BPF_JMP | BPF_JEQ | BPF_K
            || x == BPF_JMP | BPF_JEQ | BPF_X
            || x == BPF_JMP | BPF_JGE | BPF_K
            || x == BPF_JMP | BPF_JGE | BPF_X
            || x == BPF_JMP | BPF_JGT | BPF_K
            || x == BPF_JMP | BPF_JGT | BPF_X
            || x == BPF_JMP | BPF_JSET | BPF_K
            || x == BPF_JMP | BPF_JSET | BPF_X
    )
}

fn verify_program(instructions: &[ClassicBpfInstruction]) -> Result<(), ProgramError> {
    let length = instructions.len();
    if length == 0 {
        return Err(ProgramError::Empty);
    }
    if length > BPF_MAXINSNS {
        return Err(ProgramError::TooLong);
    }

    for (program_counter, instruction) in instructions.iter().enumerate() {
        let code = instruction.code;
        if !allowed_opcode(code) {
            return Err(ProgramError::InvalidOpcode {
                program_counter,
                code,
            });
        }
        match code {
            x if x == BPF_ALU | BPF_DIV | BPF_K => {
                if instruction.value == 0 {
                    return Err(ProgramError::DivisionByZero { program_counter });
                }
            }
            x if x == BPF_ALU | BPF_LSH | BPF_K || x == BPF_ALU | BPF_RSH | BPF_K => {
                if instruction.value >= 32 {
                    return Err(ProgramError::ShiftOutOfRange { program_counter });
                }
            }
            x if x == BPF_LD | BPF_MEM || x == BPF_LDX | BPF_MEM || x == BPF_ST || x == BPF_STX => {
                if instruction.value as usize >= BPF_MEMWORDS {
                    return Err(ProgramError::ScratchOutOfRange { program_counter });
                }
            }
            x if x == BPF_JMP | BPF_JA => {
                let remaining = length - program_counter - 1;
                if instruction.value as usize >= remaining {
                    return Err(ProgramError::JumpOutOfRange { program_counter });
                }
            }
            x if x & BPF_CLASS_MASK == BPF_JMP && x & BPF_OP_MASK != BPF_JA => {
                let base = program_counter + 1;
                if base + instruction.jump_true as usize >= length
                    || base + instruction.jump_false as usize >= length
                {
                    return Err(ProgramError::JumpOutOfRange { program_counter });
                }
            }
            x if x == BPF_LD | BPF_W | BPF_ABS => {
                if instruction.value & 3 != 0 {
                    return Err(ProgramError::DataOffsetUnaligned { program_counter });
                }
                if instruction.value as usize >= SECCOMP_DATA_SIZE {
                    return Err(ProgramError::DataOffsetOutOfRange { program_counter });
                }
            }
            _ => {}
        }
    }

    if !matches!(
        instructions[length - 1].code,
        x if x == BPF_RET | BPF_K || x == BPF_RET | BPF_A
    ) {
        return Err(ProgramError::MissingReturn);
    }
    verify_scratch_initialization(instructions)
}

fn verify_scratch_initialization(
    instructions: &[ClassicBpfInstruction],
) -> Result<(), ProgramError> {
    let mut incoming = Vec::new();
    incoming
        .try_reserve_exact(instructions.len())
        .map_err(|_| ProgramError::NoMemory)?;
    incoming.resize(instructions.len(), u16::MAX);

    let mut valid = 0u16;
    for (program_counter, instruction) in instructions.iter().enumerate() {
        valid &= incoming[program_counter];
        match instruction.code {
            x if x == BPF_ST || x == BPF_STX => valid |= 1 << instruction.value,
            x if x == BPF_LD | BPF_MEM || x == BPF_LDX | BPF_MEM => {
                if valid & (1 << instruction.value) == 0 {
                    return Err(ProgramError::UninitializedScratch { program_counter });
                }
            }
            x if x == BPF_JMP | BPF_JA => {
                let target = program_counter + 1 + instruction.value as usize;
                incoming[target] &= valid;
                valid = u16::MAX;
            }
            x if x & BPF_CLASS_MASK == BPF_JMP && x & BPF_OP_MASK != BPF_JA => {
                let base = program_counter + 1;
                incoming[base + instruction.jump_true as usize] &= valid;
                incoming[base + instruction.jump_false as usize] &= valid;
                valid = u16::MAX;
            }
            _ => {}
        }
    }
    Ok(())
}

fn run_verified(instructions: &[ClassicBpfInstruction], data: &SeccompData) -> u32 {
    let mut accumulator = 0u32;
    let mut index = 0u32;
    let mut scratch = [0u32; BPF_MEMWORDS];
    let mut program_counter = 0usize;

    while program_counter < instructions.len() {
        let instruction = instructions[program_counter];
        program_counter += 1;
        match instruction.code & BPF_CLASS_MASK {
            BPF_LD => match (
                instruction.code & crate::BPF_MODE_MASK,
                instruction.code & crate::BPF_SIZE_MASK,
            ) {
                (BPF_IMM, _) => accumulator = instruction.value,
                (BPF_ABS, BPF_W) => {
                    let Some(value) = data.load_word(instruction.value as usize) else {
                        return SECCOMP_RET_KILL_PROCESS;
                    };
                    accumulator = value;
                }
                (BPF_MEM, _) => accumulator = scratch[instruction.value as usize],
                (BPF_LEN, _) => accumulator = SECCOMP_DATA_SIZE as u32,
                _ => return SECCOMP_RET_KILL_PROCESS,
            },
            BPF_LDX => match instruction.code & crate::BPF_MODE_MASK {
                BPF_IMM => index = instruction.value,
                BPF_MEM => index = scratch[instruction.value as usize],
                BPF_LEN => index = SECCOMP_DATA_SIZE as u32,
                _ => return SECCOMP_RET_KILL_PROCESS,
            },
            BPF_ST => scratch[instruction.value as usize] = accumulator,
            BPF_STX => scratch[instruction.value as usize] = index,
            BPF_ALU => {
                let source = if instruction.code & BPF_SRC_MASK == BPF_X {
                    index
                } else {
                    instruction.value
                };
                accumulator = match instruction.code & BPF_OP_MASK {
                    BPF_ADD => accumulator.wrapping_add(source),
                    BPF_SUB => accumulator.wrapping_sub(source),
                    BPF_MUL => accumulator.wrapping_mul(source),
                    BPF_DIV => {
                        if source == 0 {
                            return 0;
                        }
                        accumulator / source
                    }
                    BPF_OR => accumulator | source,
                    BPF_AND => accumulator & source,
                    BPF_LSH => accumulator.wrapping_shl(source & 31),
                    BPF_RSH => accumulator.wrapping_shr(source & 31),
                    BPF_NEG => accumulator.wrapping_neg(),
                    BPF_XOR => accumulator ^ source,
                    _ => return SECCOMP_RET_KILL_PROCESS,
                };
            }
            BPF_JMP => {
                if instruction.code & BPF_OP_MASK == BPF_JA {
                    program_counter += instruction.value as usize;
                    continue;
                }
                let source = if instruction.code & BPF_SRC_MASK == BPF_X {
                    index
                } else {
                    instruction.value
                };
                let condition = match instruction.code & BPF_OP_MASK {
                    BPF_JEQ => accumulator == source,
                    BPF_JGT => accumulator > source,
                    BPF_JGE => accumulator >= source,
                    BPF_JSET => accumulator & source != 0,
                    _ => return SECCOMP_RET_KILL_PROCESS,
                };
                program_counter += if condition {
                    instruction.jump_true as usize
                } else {
                    instruction.jump_false as usize
                };
            }
            BPF_RET => {
                return if instruction.code & BPF_RVAL_MASK == BPF_A {
                    accumulator
                } else {
                    instruction.value
                };
            }
            BPF_MISC => match instruction.code & BPF_OP_MASK {
                BPF_TAX => index = accumulator,
                BPF_TXA => accumulator = index,
                _ => return SECCOMP_RET_KILL_PROCESS,
            },
            _ => return SECCOMP_RET_KILL_PROCESS,
        }
    }
    SECCOMP_RET_KILL_PROCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AUDIT_ARCH_RISCV64, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO};

    const fn stmt(code: u16, value: u32) -> ClassicBpfInstruction {
        ClassicBpfInstruction::new(code, 0, 0, value)
    }

    const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> ClassicBpfInstruction {
        ClassicBpfInstruction::new(code, jt, jf, value)
    }

    fn data() -> SeccompData {
        SeccompData {
            number: 63,
            architecture: AUDIT_ARCH_RISCV64,
            instruction_pointer: 0x1122_3344_5566_7788,
            arguments: [0x0102_0304_0506_0708, 2, 3, 4, 5, 0xa1a2_a3a4_a5a6_a7a8],
        }
    }

    #[test]
    fn rejects_empty_oversize_and_missing_return() {
        assert!(matches!(
            VerifiedProgram::try_copy_from_slice(&[]),
            Err(ProgramError::Empty)
        ));
        let mut huge = Vec::new();
        huge.try_reserve_exact(BPF_MAXINSNS + 1).unwrap();
        huge.resize(BPF_MAXINSNS + 1, stmt(BPF_RET | BPF_K, 0));
        assert!(matches!(
            VerifiedProgram::try_from_vec(huge),
            Err(ProgramError::TooLong)
        ));
        assert_eq!(
            verify_program(&[stmt(BPF_LD | BPF_IMM, 7)]),
            Err(ProgramError::MissingReturn)
        );
    }

    #[test]
    fn rejects_non_seccomp_loads_and_bad_offsets() {
        assert!(matches!(
            verify_program(&[stmt(BPF_LD | 0x10 | BPF_ABS, 0), stmt(BPF_RET | BPF_A, 0),]),
            Err(ProgramError::InvalidOpcode { .. })
        ));
        assert_eq!(
            verify_program(&[stmt(BPF_LD | BPF_W | BPF_ABS, 2), stmt(BPF_RET | BPF_A, 0),]),
            Err(ProgramError::DataOffsetUnaligned { program_counter: 0 })
        );
        assert_eq!(
            verify_program(&[stmt(BPF_LD | BPF_W | BPF_ABS, 64), stmt(BPF_RET | BPF_A, 0),]),
            Err(ProgramError::DataOffsetOutOfRange { program_counter: 0 })
        );
    }

    #[test]
    fn rejects_bad_arithmetic_and_jumps() {
        assert_eq!(
            verify_program(&[stmt(BPF_ALU | BPF_DIV | BPF_K, 0), stmt(BPF_RET | BPF_A, 0),]),
            Err(ProgramError::DivisionByZero { program_counter: 0 })
        );
        assert_eq!(
            verify_program(&[
                stmt(BPF_ALU | BPF_LSH | BPF_K, 32),
                stmt(BPF_RET | BPF_A, 0),
            ]),
            Err(ProgramError::ShiftOutOfRange { program_counter: 0 })
        );
        assert_eq!(
            verify_program(&[stmt(BPF_JMP | BPF_JA, 1), stmt(BPF_RET | BPF_K, 0),]),
            Err(ProgramError::JumpOutOfRange { program_counter: 0 })
        );
    }

    #[test]
    fn scratch_must_be_initialized_on_every_reachable_path() {
        let program = [
            jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
            stmt(BPF_ST, 0),
            stmt(BPF_LD | BPF_MEM, 0),
            stmt(BPF_RET | BPF_A, 0),
        ];
        assert_eq!(
            verify_program(&program),
            Err(ProgramError::UninitializedScratch { program_counter: 2 })
        );
    }

    #[test]
    fn evaluates_syscall_arch_ip_and_argument_words() {
        let cases = [
            (0, 63),
            (4, AUDIT_ARCH_RISCV64),
            (8, 0x5566_7788),
            (12, 0x1122_3344),
            (16, 0x0506_0708),
            (20, 0x0102_0304),
            (56, 0xa5a6_a7a8),
            (60, 0xa1a2_a3a4),
        ];
        for (offset, expected) in cases {
            let program = VerifiedProgram::try_copy_from_slice(&[
                stmt(BPF_LD | BPF_W | BPF_ABS, offset),
                stmt(BPF_RET | BPF_A, 0),
            ])
            .unwrap();
            assert_eq!(program.evaluate(&data()), expected, "offset {offset}");
        }
    }

    #[test]
    fn evaluates_branch_scratch_and_linux_action() {
        let program = VerifiedProgram::try_copy_from_slice(&[
            stmt(BPF_LD | BPF_W | BPF_ABS, 0),
            stmt(BPF_ST, 3),
            stmt(BPF_LDX | BPF_MEM, 3),
            jump(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 1),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 13),
        ])
        .unwrap();
        assert_eq!(program.evaluate(&data()), SECCOMP_RET_ALLOW);
    }

    #[test]
    fn register_divide_by_zero_returns_zero_like_linux_cbpf() {
        let program = VerifiedProgram::try_copy_from_slice(&[
            stmt(BPF_LD | BPF_IMM, 99),
            stmt(BPF_LDX | BPF_IMM, 0),
            stmt(BPF_ALU | BPF_DIV | BPF_X, 0),
            stmt(BPF_RET | BPF_A, 0),
        ])
        .unwrap();
        assert_eq!(program.evaluate(&data()), 0);
    }
}
