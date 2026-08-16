use crate::{BufferSlot, FileSlot, IoUringError, RequestDescriptor, RequestOperation, SQE_BYTES};

const IOSQE_FIXED_FILE: u8 = 1 << 0;

const IORING_OP_NOP: u8 = 0;
const IORING_OP_POLL_ADD: u8 = 6;
const IORING_OP_ASYNC_CANCEL: u8 = 14;
const IORING_OP_READ_FIXED: u8 = 4;
const IORING_OP_WRITE_FIXED: u8 = 5;
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
/// First opcode outside the Linux v6.12.35 UAPI enum.
pub const PINNED_IORING_OP_LAST: u8 = 58;

/// Pinned-Linux classification used by parsing and `REGISTER_PROBE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionOpcodeSupport {
    /// Implemented by this initial policy core.
    Supported(RequestOperation),
    /// Present in Linux v6.12.35 but not implemented by this profile.
    KnownUnsupported,
    /// Outside the Linux v6.12.35 UAPI enum.
    Unknown,
}

/// Classifies one raw opcode against Linux stable v6.12.35.
pub const fn classify_submission_opcode(opcode: u8) -> SubmissionOpcodeSupport {
    match opcode {
        IORING_OP_NOP => SubmissionOpcodeSupport::Supported(RequestOperation::Nop),
        IORING_OP_POLL_ADD => SubmissionOpcodeSupport::Supported(RequestOperation::PollAdd),
        IORING_OP_ASYNC_CANCEL => SubmissionOpcodeSupport::Supported(RequestOperation::AsyncCancel),
        IORING_OP_READ_FIXED => SubmissionOpcodeSupport::Supported(RequestOperation::Read),
        IORING_OP_WRITE_FIXED => SubmissionOpcodeSupport::Supported(RequestOperation::Write),
        IORING_OP_READ => SubmissionOpcodeSupport::Supported(RequestOperation::Read),
        IORING_OP_WRITE => SubmissionOpcodeSupport::Supported(RequestOperation::Write),
        opcode if opcode < PINNED_IORING_OP_LAST => SubmissionOpcodeSupport::KnownUnsupported,
        _ => SubmissionOpcodeSupport::Unknown,
    }
}

/// A normal descriptor or generation-checked fixed-file slot reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileTarget {
    /// Resolve this process-local descriptor through the caller's FD table.
    Descriptor(u32),
    /// Acquire a lease from this ring's registered-file table.
    Registered(FileSlot),
}

impl FileTarget {
    fn from_sqe(fd: i32, fixed: bool) -> Result<Self, IoUringError> {
        let raw = u32::try_from(fd).map_err(|_| IoUringError::InvalidFileTarget)?;
        if fixed {
            Ok(Self::Registered(FileSlot::new(raw)))
        } else {
            Ok(Self::Descriptor(raw))
        }
    }
}

/// Checked userspace I/O buffer geometry copied from one SQE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IoBuffer {
    address: u64,
    length: u32,
}

impl IoBuffer {
    /// Builds a buffer while rejecting address-length overflow.
    pub const fn new(address: u64, length: u32) -> Result<Self, IoUringError> {
        if address.checked_add(length as u64).is_none() {
            return Err(IoUringError::InvalidSubmission);
        }
        Ok(Self { address, length })
    }

    /// Raw userspace start address.
    pub const fn address(self) -> u64 {
        self.address
    }

    /// Requested byte length.
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Exclusive raw end address.
    pub const fn end(self) -> u64 {
        self.address + self.length as u64
    }
}

/// Positional READ or WRITE arguments after strict SQE decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadWriteRequest {
    file: FileTarget,
    offset: u64,
    buffer: IoBuffer,
    buffer_slot: Option<BufferSlot>,
}

impl ReadWriteRequest {
    /// File reference selected by `IOSQE_FIXED_FILE`.
    pub const fn file(self) -> FileTarget {
        self.file
    }

    /// Explicit file offset. Current-position I/O is not advertised.
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Checked userspace buffer geometry.
    pub const fn buffer(self) -> IoBuffer {
        self.buffer
    }

    /// Fixed-buffer slot selected by `READ_FIXED`/`WRITE_FIXED`, if any.
    pub const fn fixed_buffer(self) -> Option<BufferSlot> {
        self.buffer_slot
    }
}

/// One-shot POLL_ADD arguments after strict SQE decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollRequest {
    file: FileTarget,
    events: u32,
}

impl PollRequest {
    /// File reference selected by `IOSQE_FIXED_FILE`.
    pub const fn file(self) -> FileTarget {
        self.file
    }

    /// Native-endian Linux poll event bits copied from `poll32_events`.
    pub const fn events(self) -> u32 {
        self.events
    }
}

/// Operations implemented by the first pure core slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionOperation {
    /// `IORING_OP_NOP` with no result injection.
    Nop,
    /// Positional `IORING_OP_READ`.
    Read(ReadWriteRequest),
    /// Positional `IORING_OP_WRITE`.
    Write(ReadWriteRequest),
    /// One-shot `IORING_OP_POLL_ADD`.
    PollAdd(PollRequest),
    /// Default single-target `IORING_OP_ASYNC_CANCEL`, matched by user data.
    AsyncCancel {
        /// `user_data` of the request to cancel.
        target_user_data: u64,
    },
}

/// One 64-byte SQE copied once and decoded into kernel-neutral values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedSubmission {
    user_data: u64,
    operation: SubmissionOperation,
}

/// One private 64-byte SQE copy which preserves identity even when decoding
/// produces an operation-level error completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopiedSubmission {
    bytes: [u8; SQE_BYTES as usize],
}

impl CopiedSubmission {
    /// Takes ownership of the adapter's single stable SQE copy.
    pub const fn new(bytes: [u8; SQE_BYTES as usize]) -> Self {
        Self { bytes }
    }

    /// Raw operation byte used by probe/error classification.
    pub const fn opcode(&self) -> u8 {
        self.bytes[0]
    }

    /// Opaque user value available even if full operation decoding fails.
    pub fn user_data(&self) -> u64 {
        read_u64(&self.bytes, 32)
    }

    /// Descriptor used to reserve terminal capacity before full decode.
    pub fn descriptor(&self) -> RequestDescriptor {
        let operation = match classify_submission_opcode(self.opcode()) {
            SubmissionOpcodeSupport::Supported(operation) => operation,
            SubmissionOpcodeSupport::KnownUnsupported | SubmissionOpcodeSupport::Unknown => {
                RequestOperation::Rejected(self.opcode())
            }
        };
        RequestDescriptor::new(self.user_data(), operation)
    }

    /// Strictly decodes the private copy.
    pub fn parse(self) -> Result<ParsedSubmission, IoUringError> {
        ParsedSubmission::parse_copied(self.bytes)
    }
}

impl ParsedSubmission {
    /// Parses an already copied SQE without constructing a raw C union or enum.
    ///
    /// Integer fields use the little-endian Linux ABI of supported x86_64
    /// consumers. The parser accepts only the operation and flag subset that
    /// this crate can model.
    pub fn parse(bytes: [u8; SQE_BYTES as usize]) -> Result<Self, IoUringError> {
        CopiedSubmission::new(bytes).parse()
    }

    fn parse_copied(bytes: [u8; SQE_BYTES as usize]) -> Result<Self, IoUringError> {
        let opcode = bytes[0];
        let sqe_flags = bytes[1];
        let ioprio = read_u16(&bytes, 2);
        let fd = read_i32(&bytes, 4);
        let offset = read_u64(&bytes, 8);
        let address = read_u64(&bytes, 16);
        let length = read_u32(&bytes, 24);
        let operation_flags = read_u32(&bytes, 28);
        let user_data = read_u64(&bytes, 32);
        let buffer_index = read_u16(&bytes, 40);
        let personality = read_u16(&bytes, 42);
        let splice_fd_in = read_i32(&bytes, 44);

        let operation = match opcode {
            IORING_OP_NOP => {
                require_submission_flags(sqe_flags, 0)?;
                if ioprio != 0 || personality != 0 || operation_flags != 0 {
                    return Err(IoUringError::UnsupportedOperationFlags);
                }
                SubmissionOperation::Nop
            }
            IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED | IORING_OP_READ | IORING_OP_WRITE => {
                require_submission_flags(sqe_flags, IOSQE_FIXED_FILE)?;
                let fixed_buffer = matches!(opcode, IORING_OP_READ_FIXED | IORING_OP_WRITE_FIXED);
                if ioprio != 0
                    || personality != 0
                    || (!fixed_buffer && buffer_index != 0)
                    || operation_flags != 0
                    || splice_fd_in != 0
                {
                    return Err(IoUringError::UnsupportedOperationFlags);
                }
                if offset == u64::MAX {
                    return Err(IoUringError::CurrentPositionUnsupported);
                }
                let request = ReadWriteRequest {
                    file: FileTarget::from_sqe(fd, sqe_flags & IOSQE_FIXED_FILE != 0)?,
                    offset,
                    buffer: IoBuffer::new(address, length)?,
                    buffer_slot: fixed_buffer.then(|| BufferSlot::new(u32::from(buffer_index))),
                };
                if opcode == IORING_OP_READ_FIXED || opcode == IORING_OP_READ {
                    SubmissionOperation::Read(request)
                } else {
                    SubmissionOperation::Write(request)
                }
            }
            IORING_OP_POLL_ADD => {
                require_submission_flags(sqe_flags, IOSQE_FIXED_FILE)?;
                if ioprio != 0
                    || personality != 0
                    || buffer_index != 0
                    || offset != 0
                    || address != 0
                    || length != 0
                {
                    return Err(IoUringError::UnsupportedOperationFlags);
                }
                SubmissionOperation::PollAdd(PollRequest {
                    file: FileTarget::from_sqe(fd, sqe_flags & IOSQE_FIXED_FILE != 0)?,
                    events: operation_flags,
                })
            }
            IORING_OP_ASYNC_CANCEL => {
                require_submission_flags(sqe_flags, 0)?;
                if ioprio != 0
                    || personality != 0
                    || offset != 0
                    || operation_flags != 0
                    || splice_fd_in != 0
                {
                    return Err(IoUringError::UnsupportedOperationFlags);
                }
                SubmissionOperation::AsyncCancel {
                    target_user_data: address,
                }
            }
            opcode if opcode < PINNED_IORING_OP_LAST => {
                return Err(IoUringError::UnsupportedOpcode);
            }
            _ => return Err(IoUringError::UnknownOpcode),
        };

        Ok(Self {
            user_data,
            operation,
        })
    }

    /// Opaque userspace value copied into the terminal CQE.
    pub const fn user_data(self) -> u64 {
        self.user_data
    }

    /// Strictly decoded operation arguments.
    pub const fn operation(self) -> SubmissionOperation {
        self.operation
    }

    /// Produces the request-table descriptor used for cancellation matching.
    pub const fn descriptor(self) -> RequestDescriptor {
        RequestDescriptor::new(
            self.user_data,
            match self.operation {
                SubmissionOperation::Nop => RequestOperation::Nop,
                SubmissionOperation::Read(_) => RequestOperation::Read,
                SubmissionOperation::Write(_) => RequestOperation::Write,
                SubmissionOperation::PollAdd(_) => RequestOperation::PollAdd,
                SubmissionOperation::AsyncCancel { .. } => RequestOperation::AsyncCancel,
            },
        )
    }
}

fn require_submission_flags(bits: u8, allowed: u8) -> Result<(), IoUringError> {
    if bits & !allowed == 0 {
        Ok(())
    } else {
        Err(IoUringError::UnsupportedSubmissionFlags)
    }
}

fn read_u16(bytes: &[u8; SQE_BYTES as usize], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8; SQE_BYTES as usize], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_i32(bytes: &[u8; SQE_BYTES as usize], offset: usize) -> i32 {
    i32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8; SQE_BYTES as usize], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqe(opcode: u8, user_data: u64) -> [u8; SQE_BYTES as usize] {
        let mut bytes = [0; SQE_BYTES as usize];
        bytes[0] = opcode;
        bytes[32..40].copy_from_slice(&user_data.to_le_bytes());
        bytes
    }

    #[test]
    fn copied_submission_preserves_identity_before_decode() {
        let copied = CopiedSubmission::new(sqe(1, 0x1122_3344_5566_7788));
        assert_eq!(copied.opcode(), 1);
        assert_eq!(copied.user_data(), 0x1122_3344_5566_7788);
        assert_eq!(
            copied.descriptor().operation(),
            RequestOperation::Rejected(1)
        );
        assert_eq!(copied.parse(), Err(IoUringError::UnsupportedOpcode));
    }

    #[test]
    fn nop_and_positioned_write_decode_without_hidden_state() {
        let nop = ParsedSubmission::parse(sqe(IORING_OP_NOP, 5)).unwrap();
        assert_eq!(nop.operation(), SubmissionOperation::Nop);

        let mut bytes = sqe(IORING_OP_WRITE, 6);
        bytes[4..8].copy_from_slice(&4_i32.to_le_bytes());
        bytes[8..16].copy_from_slice(&9_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x2000_u64.to_le_bytes());
        bytes[24..28].copy_from_slice(&32_u32.to_le_bytes());
        let write = ParsedSubmission::parse(bytes).unwrap();
        let SubmissionOperation::Write(write) = write.operation() else {
            panic!("expected write request");
        };
        assert_eq!(write.file(), FileTarget::Descriptor(4));
        assert_eq!(write.offset(), 9);
        assert_eq!(write.buffer(), IoBuffer::new(0x2000, 32).unwrap());
    }

    #[test]
    fn pointer_overflow_and_unimplemented_flags_are_distinct() {
        let mut bytes = sqe(IORING_OP_READ, 1);
        bytes[4..8].copy_from_slice(&4_i32.to_le_bytes());
        bytes[16..24].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        bytes[24..28].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            ParsedSubmission::parse(bytes),
            Err(IoUringError::InvalidSubmission)
        );

        bytes[16..24].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[1] = 1 << 4;
        assert_eq!(
            ParsedSubmission::parse(bytes),
            Err(IoUringError::UnsupportedSubmissionFlags)
        );
        bytes[1] = 0;
        bytes[28..32].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            ParsedSubmission::parse(bytes),
            Err(IoUringError::UnsupportedOperationFlags)
        );
    }

    #[test]
    fn pinned_known_and_unknown_opcodes_are_distinct() {
        assert_eq!(
            ParsedSubmission::parse(sqe(PINNED_IORING_OP_LAST - 1, 1)),
            Err(IoUringError::UnsupportedOpcode)
        );
        assert_eq!(
            ParsedSubmission::parse(sqe(PINNED_IORING_OP_LAST, 1)),
            Err(IoUringError::UnknownOpcode)
        );
        assert_eq!(
            classify_submission_opcode(PINNED_IORING_OP_LAST),
            SubmissionOpcodeSupport::Unknown
        );
    }

    #[test]
    fn poll_add_reads_all_32_event_bits() {
        let mut bytes = sqe(IORING_OP_POLL_ADD, 9);
        bytes[4..8].copy_from_slice(&3_i32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0x8000_0001_u32.to_le_bytes());
        let parsed = ParsedSubmission::parse(bytes).unwrap();
        let SubmissionOperation::PollAdd(poll) = parsed.operation() else {
            panic!("expected poll request");
        };
        assert_eq!(poll.file(), FileTarget::Descriptor(3));
        assert_eq!(poll.events(), 0x8000_0001);
    }

    #[test]
    fn positioned_io_rejects_current_position_and_accepts_fixed_file() {
        let mut bytes = sqe(IORING_OP_READ, 9);
        bytes[1] = IOSQE_FIXED_FILE;
        bytes[4..8].copy_from_slice(&2_i32.to_le_bytes());
        bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            ParsedSubmission::parse(bytes),
            Err(IoUringError::CurrentPositionUnsupported)
        );
        bytes[8..16].copy_from_slice(&7_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[24..28].copy_from_slice(&16_u32.to_le_bytes());
        let parsed = ParsedSubmission::parse(bytes).unwrap();
        let SubmissionOperation::Read(read) = parsed.operation() else {
            panic!("expected read request");
        };
        assert_eq!(read.file(), FileTarget::Registered(FileSlot::new(2)));
        assert_eq!(read.offset(), 7);
        assert_eq!(read.buffer().end(), 0x1010);
    }

    #[test]
    fn fixed_buffer_io_decodes_slot_and_exact_range() {
        let mut bytes = sqe(IORING_OP_WRITE_FIXED, 10);
        bytes[1] = IOSQE_FIXED_FILE;
        bytes[4..8].copy_from_slice(&3_i32.to_le_bytes());
        bytes[8..16].copy_from_slice(&11_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&0x4010_u64.to_le_bytes());
        bytes[24..28].copy_from_slice(&24_u32.to_le_bytes());
        bytes[40..42].copy_from_slice(&7_u16.to_le_bytes());
        let parsed = ParsedSubmission::parse(bytes).unwrap();
        let SubmissionOperation::Write(write) = parsed.operation() else {
            panic!("expected fixed-buffer write request");
        };
        assert_eq!(write.file(), FileTarget::Registered(FileSlot::new(3)));
        assert_eq!(write.fixed_buffer(), Some(BufferSlot::new(7)));
        assert_eq!(write.buffer(), IoBuffer::new(0x4010, 24).unwrap());
        assert_eq!(
            classify_submission_opcode(IORING_OP_READ_FIXED),
            SubmissionOpcodeSupport::Supported(RequestOperation::Read)
        );
    }

    #[test]
    fn async_cancel_decodes_default_user_data_selector() {
        let mut bytes = sqe(IORING_OP_ASYNC_CANCEL, 11);
        bytes[4..8].copy_from_slice(&(-1_i32).to_le_bytes());
        bytes[16..24].copy_from_slice(&77_u64.to_le_bytes());
        let parsed = ParsedSubmission::parse(bytes).unwrap();
        assert_eq!(
            parsed.operation(),
            SubmissionOperation::AsyncCancel {
                target_user_data: 77
            }
        );
    }
}
