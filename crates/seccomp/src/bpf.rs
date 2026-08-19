use alloc::vec::Vec;

use axcbpf::{CodeImage, Input, InputProfile, LoadWidth, Program, VerifyError, opcode};

use crate::{BPF_MAXINSNS, SECCOMP_DATA_SIZE};

/// Linux `struct sock_filter`, the eight-byte classic-BPF instruction format.
pub use axcbpf::Instruction as ClassicBpfInstruction;

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
    /// Returns the exact 64-byte native-endian byte view consumed by a
    /// native seccomp translator.
    ///
    /// The returned object is intentionally owned: it keeps the input ABI
    /// explicit without exposing a reference created through an unsafe cast
    /// or relying on a packed representation. On x86_64 this is the native
    /// `struct seccomp_data` layout and is safe to pass to an executor for
    /// the duration of one evaluation.
    pub fn native_bytes(&self) -> [u8; SECCOMP_DATA_SIZE] {
        let mut bytes = [0u8; SECCOMP_DATA_SIZE];
        bytes[0..4].copy_from_slice(&self.number.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.architecture.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.instruction_pointer.to_ne_bytes());
        for (index, argument) in self.arguments.iter().copied().enumerate() {
            let start = 16 + index * 8;
            bytes[start..start + 8].copy_from_slice(&argument.to_ne_bytes());
        }
        bytes
    }

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

/// Narrow object-safe execution contract for one immutable seccomp program.
///
/// Implementations must not allocate, mutate policy state, or inspect the
/// current task. The input is the 64-byte native seccomp-data view. The
/// interpreter remains the semantic oracle and is used whenever no executor
/// was successfully published.
pub trait SeccompExecutor: Send + Sync {
    /// Evaluates one native seccomp-data byte view and returns a raw action.
    fn execute(&self, data: &[u8]) -> u32;
}

impl Input for SeccompData {
    fn len(&self) -> u32 {
        SECCOMP_DATA_SIZE as u32
    }

    fn load(&self, offset: u32, width: LoadWidth) -> Option<u32> {
        if width != LoadWidth::Word {
            return None;
        }
        self.load_word(offset as usize)
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

/// Rejection reason produced while validating an untrusted seccomp program.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProgramError {
    /// The program contains no instructions.
    Empty,
    /// The program exceeds Linux's 4096-instruction limit.
    TooLong,
    /// Allocation for validation metadata or the immutable program failed.
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
    /// A future mechanism rejection has no seccomp-specific mapping yet.
    MechanismRejected,
}

impl ProgramError {
    /// Returns whether validation failed because an allocation was unavailable.
    pub const fn is_no_memory(self) -> bool {
        matches!(self, Self::NoMemory)
    }
}

/// A verified immutable seccomp classic-BPF program.
#[derive(Debug)]
pub struct VerifiedProgram {
    program: Program,
    path_charge: usize,
}

impl VerifiedProgram {
    /// Validates and takes ownership of a complete userspace copy without
    /// allocating a second instruction buffer.
    pub fn try_from_vec(instructions: Vec<ClassicBpfInstruction>) -> Result<Self, ProgramError> {
        verify_seccomp_profile(&instructions)?;
        let path_charge = linux_v6_12_unblinded_migration_charge(&instructions);
        let program = Program::try_from_vec(instructions).map_err(map_mechanism_error)?;
        Ok(Self {
            program,
            path_charge,
        })
    }

    /// Fallibly copies and validates a program.
    pub fn try_copy_from_slice(
        instructions: &[ClassicBpfInstruction],
    ) -> Result<Self, ProgramError> {
        verify_seccomp_profile(instructions)?;
        let path_charge = linux_v6_12_unblinded_migration_charge(instructions);
        let program = Program::verify(instructions).map_err(map_mechanism_error)?;
        Ok(Self {
            program,
            path_charge,
        })
    }

    /// Returns the classic-BPF instruction count.
    pub fn len(&self) -> usize {
        self.program.len()
    }

    /// Returns whether this program is empty. Verified programs are never
    /// empty; this method is provided alongside [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.program.is_empty()
    }

    /// Returns the Linux v6.12 unblinded cBPF-to-eBPF migration charge used
    /// for stacked seccomp path accounting.
    ///
    /// Linux accounts the converted `bpf_prog::len`, not the userspace cBPF
    /// length. TheKernel has no eBPF JIT or constant blinding, so this stable
    /// baseline deliberately excludes architecture-specific JIT hardening.
    pub fn path_charge(&self) -> usize {
        self.path_charge
    }

    /// Translates this verified program for the x86_64 native seccomp-data
    /// ABI. The returned image is still non-executable; its owner must apply
    /// the platform's W^X publication policy.
    pub fn translate_native(&self) -> Result<CodeImage, axcbpf::TranslationError> {
        self.program
            .translate_with_profile(InputProfile::NativeAlignedWords)
    }

    /// Returns the immutable verified instruction sequence.
    pub fn instructions(&self) -> &[ClassicBpfInstruction] {
        self.program.instructions()
    }

    /// Evaluates the program without allocation or unbounded control flow.
    pub fn evaluate(&self, data: &SeccompData) -> u32 {
        self.program.evaluate(data)
    }
}

const LINUX_V6_12_CLASSIC_MIGRATION_PROLOGUE: usize = 3;

fn linux_v6_12_unblinded_migration_charge(instructions: &[ClassicBpfInstruction]) -> usize {
    LINUX_V6_12_CLASSIC_MIGRATION_PROLOGUE
        + instructions
            .iter()
            .map(linux_v6_12_unblinded_instruction_charge)
            .sum::<usize>()
}

fn linux_v6_12_unblinded_instruction_charge(instruction: &ClassicBpfInstruction) -> usize {
    match instruction.code {
        // Linux guards register division by zero before the converted ALU
        // instruction: normalize X, branch, zero A, exit, then divide.
        opcode::ALU_DIV_X => 5,
        // A constant return becomes MOV32 plus EXIT.
        opcode::RET_K => 2,
        opcode::JMP_JEQ_K | opcode::JMP_JGE_K | opcode::JMP_JGT_K | opcode::JMP_JSET_K => {
            usize::from((instruction.k as i32) < 0) + converted_conditional_jump_charge(instruction)
        }
        opcode::JMP_JEQ_X | opcode::JMP_JGE_X | opcode::JMP_JGT_X | opcode::JMP_JSET_X => {
            converted_conditional_jump_charge(instruction)
        }
        _ => 1,
    }
}

fn converted_conditional_jump_charge(instruction: &ClassicBpfInstruction) -> usize {
    if instruction.jf == 0
        || (instruction.jt == 0
            && !matches!(instruction.code, opcode::JMP_JSET_K | opcode::JMP_JSET_X))
    {
        1
    } else {
        // A conditional branch with two non-fallthrough targets becomes the
        // conditional jump followed by an unconditional JA. JSET has no
        // inverse form, so it also needs JA when only the true side falls
        // through.
        2
    }
}

fn verify_seccomp_profile(instructions: &[ClassicBpfInstruction]) -> Result<(), ProgramError> {
    if instructions.is_empty() {
        return Err(ProgramError::Empty);
    }
    if instructions.len() > BPF_MAXINSNS {
        return Err(ProgramError::TooLong);
    }
    for (program_counter, instruction) in instructions.iter().enumerate() {
        if !allowed_seccomp_opcode(instruction.code) {
            return Err(ProgramError::InvalidOpcode {
                program_counter,
                code: instruction.code,
            });
        }
        if instruction.code == opcode::LD_W_ABS {
            if instruction.k & 3 != 0 {
                return Err(ProgramError::DataOffsetUnaligned { program_counter });
            }
            if instruction.k as usize >= SECCOMP_DATA_SIZE {
                return Err(ProgramError::DataOffsetOutOfRange { program_counter });
            }
        }
    }
    Ok(())
}

const fn allowed_seccomp_opcode(code: u16) -> bool {
    matches!(
        code,
        opcode::LD_W_ABS
            | opcode::LD_LEN
            | opcode::LDX_LEN
            | opcode::RET_K
            | opcode::RET_A
            | opcode::ALU_ADD_K
            | opcode::ALU_ADD_X
            | opcode::ALU_SUB_K
            | opcode::ALU_SUB_X
            | opcode::ALU_MUL_K
            | opcode::ALU_MUL_X
            | opcode::ALU_DIV_K
            | opcode::ALU_DIV_X
            | opcode::ALU_AND_K
            | opcode::ALU_AND_X
            | opcode::ALU_OR_K
            | opcode::ALU_OR_X
            | opcode::ALU_XOR_K
            | opcode::ALU_XOR_X
            | opcode::ALU_LSH_K
            | opcode::ALU_LSH_X
            | opcode::ALU_RSH_K
            | opcode::ALU_RSH_X
            | opcode::ALU_NEG
            | opcode::LD_IMM
            | opcode::LDX_IMM
            | opcode::MISC_TAX
            | opcode::MISC_TXA
            | opcode::LD_MEM
            | opcode::LDX_MEM
            | opcode::ST
            | opcode::STX
            | opcode::JMP_JA
            | opcode::JMP_JEQ_K
            | opcode::JMP_JEQ_X
            | opcode::JMP_JGE_K
            | opcode::JMP_JGE_X
            | opcode::JMP_JGT_K
            | opcode::JMP_JGT_X
            | opcode::JMP_JSET_K
            | opcode::JMP_JSET_X
    )
}

fn map_mechanism_error(error: VerifyError) -> ProgramError {
    match error {
        VerifyError::Empty => ProgramError::Empty,
        VerifyError::TooLong { .. } => ProgramError::TooLong,
        VerifyError::NoMemory => ProgramError::NoMemory,
        VerifyError::UnsupportedOpcode { pc, code } => ProgramError::InvalidOpcode {
            program_counter: pc,
            code,
        },
        VerifyError::ImmediateDivisionByZero { pc } => ProgramError::DivisionByZero {
            program_counter: pc,
        },
        VerifyError::ImmediateShiftOutOfRange { pc, .. } => ProgramError::ShiftOutOfRange {
            program_counter: pc,
        },
        VerifyError::ScratchOutOfRange { pc, .. } => ProgramError::ScratchOutOfRange {
            program_counter: pc,
        },
        VerifyError::ScratchUninitialized { pc, .. } => ProgramError::UninitializedScratch {
            program_counter: pc,
        },
        VerifyError::JumpOutOfRange { pc } => ProgramError::JumpOutOfRange {
            program_counter: pc,
        },
        VerifyError::MissingFinalReturn => ProgramError::MissingReturn,
        VerifyError::UnsupportedAncillaryLoad { .. } => ProgramError::MechanismRejected,
        _ => ProgramError::MechanismRejected,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::mem::{align_of, offset_of, size_of};

    use super::*;
    use crate::{AUDIT_ARCH_X86_64, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO};

    const fn stmt(code: u16, value: u32) -> ClassicBpfInstruction {
        ClassicBpfInstruction::statement(code, value)
    }

    const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> ClassicBpfInstruction {
        ClassicBpfInstruction::jump(code, value, jt, jf)
    }

    fn data() -> SeccompData {
        SeccompData {
            number: 63,
            architecture: AUDIT_ARCH_X86_64,
            instruction_pointer: 0x1122_3344_5566_7788,
            arguments: [0x0102_0304_0506_0708, 2, 3, 4, 5, 0xa1a2_a3a4_a5a6_a7a8],
        }
    }

    #[test]
    fn seccomp_data_and_audit_arch_matches_linux_x86_64_abi() {
        assert_eq!(size_of::<SeccompData>(), 64);
        assert_eq!(align_of::<SeccompData>(), 8);
        assert_eq!(offset_of!(SeccompData, number), 0);
        assert_eq!(offset_of!(SeccompData, architecture), 4);
        assert_eq!(offset_of!(SeccompData, instruction_pointer), 8);
        assert_eq!(offset_of!(SeccompData, arguments), 16);
        assert_eq!(AUDIT_ARCH_X86_64, 0xc000_003e);
    }

    #[test]
    fn native_bytes_preserve_the_wire_layout_without_aliasing() {
        let bytes = data().native_bytes();
        assert_eq!(&bytes[0..4], &63i32.to_ne_bytes());
        assert_eq!(&bytes[4..8], &AUDIT_ARCH_X86_64.to_ne_bytes());
        assert_eq!(&bytes[8..16], &0x1122_3344_5566_7788u64.to_ne_bytes());
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_ne_bytes());
        assert_eq!(bytes.len(), SECCOMP_DATA_SIZE);
    }

    #[test]
    fn verified_program_exposes_only_the_native_seccomp_translation_profile() {
        let program = VerifiedProgram::try_copy_from_slice(&[
            stmt(opcode::LD_W_ABS, 4),
            stmt(opcode::RET_A, 0),
        ])
        .unwrap();
        let image = program.translate_native().unwrap();
        assert_eq!(image.profile(), InputProfile::NativeAlignedWords);
        image.validate().unwrap();
        let bytes = data().native_bytes();
        let native = axcbpf::NativeWordInput::new(&bytes);
        assert_eq!(image.evaluate(&native), program.evaluate(&data()));
    }

    #[test]
    fn rejects_empty_oversize_and_missing_return() {
        assert!(matches!(
            VerifiedProgram::try_copy_from_slice(&[]),
            Err(ProgramError::Empty)
        ));
        let mut huge = Vec::new();
        huge.try_reserve_exact(BPF_MAXINSNS + 1).unwrap();
        huge.resize(BPF_MAXINSNS + 1, stmt(opcode::RET_K, 0));
        assert!(matches!(
            VerifiedProgram::try_from_vec(huge),
            Err(ProgramError::TooLong)
        ));
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&[stmt(opcode::LD_IMM, 7)]).unwrap_err(),
            ProgramError::MissingReturn
        );
    }

    #[test]
    fn rejects_non_seccomp_loads_modulo_and_bad_offsets() {
        for code in [
            opcode::LD_H_ABS,
            opcode::LD_W_IND,
            opcode::LDX_B_MSH,
            opcode::ALU_MOD_K,
        ] {
            assert!(matches!(
                VerifiedProgram::try_copy_from_slice(&[stmt(code, 0), stmt(opcode::RET_A, 0),]),
                Err(ProgramError::InvalidOpcode { .. })
            ));
        }
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&[
                stmt(opcode::LD_W_ABS, 2),
                stmt(opcode::RET_A, 0),
            ])
            .unwrap_err(),
            ProgramError::DataOffsetUnaligned { program_counter: 0 }
        );
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&[
                stmt(opcode::LD_W_ABS, 64),
                stmt(opcode::RET_A, 0),
            ])
            .unwrap_err(),
            ProgramError::DataOffsetOutOfRange { program_counter: 0 }
        );
    }

    #[test]
    fn rejects_bad_arithmetic_and_jumps() {
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&[
                stmt(opcode::ALU_DIV_K, 0),
                stmt(opcode::RET_A, 0),
            ])
            .unwrap_err(),
            ProgramError::DivisionByZero { program_counter: 0 }
        );
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&[
                stmt(opcode::ALU_LSH_K, 32),
                stmt(opcode::RET_A, 0),
            ])
            .unwrap_err(),
            ProgramError::ShiftOutOfRange { program_counter: 0 }
        );
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&[
                stmt(opcode::JMP_JA, 1),
                stmt(opcode::RET_K, 0),
            ])
            .unwrap_err(),
            ProgramError::JumpOutOfRange { program_counter: 0 }
        );
    }

    #[test]
    fn path_charge_matches_linux_v6_12_ret_k_and_div_x_expansion() {
        let ret_k = VerifiedProgram::try_copy_from_slice(&[stmt(opcode::RET_K, SECCOMP_RET_ALLOW)])
            .unwrap();
        assert_eq!(ret_k.len(), 1);
        assert_eq!(ret_k.path_charge(), 5); // Three-prologue + MOV32 + EXIT.

        let mut maximum_ret_k = Vec::new();
        maximum_ret_k.try_reserve_exact(BPF_MAXINSNS).unwrap();
        maximum_ret_k.resize(BPF_MAXINSNS, stmt(opcode::RET_K, SECCOMP_RET_ALLOW));
        let maximum_ret_k = VerifiedProgram::try_from_vec(maximum_ret_k).unwrap();
        assert_eq!(maximum_ret_k.len(), BPF_MAXINSNS);
        assert_eq!(maximum_ret_k.path_charge(), 3 + 2 * BPF_MAXINSNS);

        let ret_a = VerifiedProgram::try_copy_from_slice(&[stmt(opcode::RET_A, 0)]).unwrap();
        assert_eq!(ret_a.path_charge(), 4); // Three-prologue + EXIT.

        let div_x = VerifiedProgram::try_copy_from_slice(&[
            stmt(opcode::ALU_DIV_X, 0),
            stmt(opcode::RET_A, 0),
        ])
        .unwrap();
        assert_eq!(div_x.len(), 2);
        assert_eq!(div_x.path_charge(), 9); // Three-prologue + five + EXIT.
    }

    #[test]
    fn path_charge_distinguishes_reversible_and_non_reversible_conditionals() {
        let reversible = VerifiedProgram::try_copy_from_slice(&[
            jump(opcode::JMP_JEQ_K, 7, 0, 1),
            stmt(opcode::RET_K, SECCOMP_RET_ALLOW),
            stmt(opcode::RET_K, SECCOMP_RET_ERRNO),
        ])
        .unwrap();
        assert_eq!(reversible.path_charge(), 8);

        // Linux can invert JEQ when the true target falls through, but JSET
        // has no inverse opcode and therefore also needs an unconditional JA.
        let non_reversible = VerifiedProgram::try_copy_from_slice(&[
            jump(opcode::JMP_JSET_K, 7, 0, 1),
            stmt(opcode::RET_K, SECCOMP_RET_ALLOW),
            stmt(opcode::RET_K, SECCOMP_RET_ERRNO),
        ])
        .unwrap();
        assert_eq!(non_reversible.path_charge(), 9);

        // A negative K compare first materializes the unsigned immediate in
        // a temporary eBPF register, adding one more converted instruction.
        let negative_immediate = VerifiedProgram::try_copy_from_slice(&[
            jump(opcode::JMP_JEQ_K, u32::MAX, 0, 1),
            stmt(opcode::RET_K, SECCOMP_RET_ALLOW),
            stmt(opcode::RET_K, SECCOMP_RET_ERRNO),
        ])
        .unwrap();
        assert_eq!(negative_immediate.path_charge(), 9);
    }

    #[test]
    fn scratch_must_be_initialized_on_every_reachable_path() {
        let program = [
            jump(opcode::JMP_JEQ_K, 0, 0, 1),
            stmt(opcode::ST, 0),
            stmt(opcode::LD_MEM, 0),
            stmt(opcode::RET_A, 0),
        ];
        assert_eq!(
            VerifiedProgram::try_copy_from_slice(&program).unwrap_err(),
            ProgramError::UninitializedScratch { program_counter: 2 }
        );
    }

    #[test]
    fn evaluates_syscall_arch_ip_and_argument_words() {
        let cases = [
            (0, 63),
            (4, AUDIT_ARCH_X86_64),
            (8, 0x5566_7788),
            (12, 0x1122_3344),
            (16, 0x0506_0708),
            (20, 0x0102_0304),
            (56, 0xa5a6_a7a8),
            (60, 0xa1a2_a3a4),
        ];
        for (offset, expected) in cases {
            let program = VerifiedProgram::try_copy_from_slice(&[
                stmt(opcode::LD_W_ABS, offset),
                stmt(opcode::RET_A, 0),
            ])
            .unwrap();
            assert_eq!(program.evaluate(&data()), expected, "offset {offset}");
        }
    }

    #[test]
    fn evaluates_length_branch_scratch_and_linux_action() {
        let program = VerifiedProgram::try_copy_from_slice(&[
            stmt(opcode::LD_LEN, 0),
            stmt(opcode::ST, 3),
            stmt(opcode::LDX_LEN, 0),
            jump(opcode::JMP_JEQ_X, 0, 0, 1),
            stmt(opcode::RET_K, SECCOMP_RET_ALLOW),
            stmt(opcode::RET_K, SECCOMP_RET_ERRNO | 13),
        ])
        .unwrap();
        assert_eq!(program.evaluate(&data()), SECCOMP_RET_ALLOW);
        assert_eq!(program.instructions().len(), 6);
    }

    #[test]
    fn register_divide_by_zero_returns_zero_like_linux_cbpf() {
        let program = VerifiedProgram::try_copy_from_slice(&[
            stmt(opcode::LD_IMM, 99),
            stmt(opcode::LDX_IMM, 0),
            stmt(opcode::ALU_DIV_X, 0),
            stmt(opcode::RET_A, 0),
        ])
        .unwrap();
        assert_eq!(program.evaluate(&data()), 0);
    }
}
