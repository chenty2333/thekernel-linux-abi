use crate::IoUringError;

/// Strictly decoded `io_uring_enter` flags supported by the initial profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EnterFlags(u32);

impl EnterFlags {
    /// Wait until the requested minimum completion count is available.
    pub const GETEVENTS: Self = Self(1 << 0);
    /// Complete initial supported enter flag set.
    pub const SUPPORTED: Self = Self(Self::GETEVENTS.0);

    /// Rejects `SQ_WAKEUP`, `SQ_WAIT`, `EXT_ARG`, registered-ring, and timer
    /// modifiers before submission state changes.
    pub const fn from_bits(bits: u32) -> Result<Self, IoUringError> {
        if bits & !Self::SUPPORTED.0 == 0 {
            Ok(Self(bits))
        } else {
            Err(IoUringError::UnsupportedEnterFlags)
        }
    }

    /// Linux-compatible raw enter bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether all selected bits are present.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Optional legacy signal-mask copyin requested for one enter invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySignalMask {
    /// No temporary signal mask is requested.
    None,
    /// Copy exactly the consumer-provided native `SignalSet` size from this
    /// userspace address, install it for the wait, and restore on every exit.
    Address(u64),
}

/// Copied scalar `io_uring_enter` arguments after strict initial decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnterRequest {
    to_submit: u32,
    minimum_complete: u32,
    flags: EnterFlags,
    signal_mask: LegacySignalMask,
}

impl EnterRequest {
    /// Validates initial enter flags and legacy signal-mask geometry.
    ///
    /// `expected_signal_set_bytes` is supplied by the signal ABI adapter. A
    /// present legacy mask must match it exactly. The returned value does not
    /// install a mask; the adapter must use a restoration guard spanning every
    /// success, interruption, timeout, and error exit.
    pub const fn from_raw(
        to_submit: u32,
        minimum_complete: u32,
        flags: u32,
        signal_mask_address: u64,
        signal_mask_bytes: u64,
        expected_signal_set_bytes: u64,
    ) -> Result<Self, IoUringError> {
        let flags = match EnterFlags::from_bits(flags) {
            Ok(flags) => flags,
            Err(error) => return Err(error),
        };
        let signal_mask = if signal_mask_address == 0 {
            if signal_mask_bytes != 0 && signal_mask_bytes != expected_signal_set_bytes {
                return Err(IoUringError::InvalidSignalMaskArgument);
            }
            LegacySignalMask::None
        } else {
            if expected_signal_set_bytes == 0 || signal_mask_bytes != expected_signal_set_bytes {
                return Err(IoUringError::InvalidSignalMaskArgument);
            }
            LegacySignalMask::Address(signal_mask_address)
        };
        Ok(Self {
            to_submit,
            minimum_complete,
            flags,
            signal_mask,
        })
    }

    /// Maximum SQ entries requested by this invocation.
    pub const fn to_submit(self) -> u32 {
        self.to_submit
    }

    /// Completion count requested by `GETEVENTS` waiting.
    pub const fn minimum_complete(self) -> u32 {
        self.minimum_complete
    }

    /// Strictly decoded enter flags.
    pub const fn flags(self) -> EnterFlags {
        self.flags
    }

    /// Optional exact-size legacy mask request.
    pub const fn signal_mask(self) -> LegacySignalMask {
        self.signal_mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_getevents_is_supported() {
        let request = EnterRequest::from_raw(3, 1, EnterFlags::GETEVENTS.bits(), 0, 0, 8).unwrap();
        assert_eq!(request.to_submit(), 3);
        assert_eq!(request.minimum_complete(), 1);
        assert!(request.flags().contains(EnterFlags::GETEVENTS));
        assert_eq!(
            EnterRequest::from_raw(0, 0, 1 << 3, 0, 0, 8),
            Err(IoUringError::UnsupportedEnterFlags)
        );
    }

    #[test]
    fn legacy_signal_mask_requires_the_exact_consumer_size() {
        assert_eq!(
            EnterRequest::from_raw(0, 0, 0, 0x1000, 8, 8)
                .unwrap()
                .signal_mask(),
            LegacySignalMask::Address(0x1000)
        );
        assert_eq!(
            EnterRequest::from_raw(0, 0, 0, 0x1000, 16, 8),
            Err(IoUringError::InvalidSignalMaskArgument)
        );
        assert_eq!(
            EnterRequest::from_raw(0, 0, 0, 0, 8, 16),
            Err(IoUringError::InvalidSignalMaskArgument)
        );
        assert_eq!(
            EnterRequest::from_raw(0, 0, 0, 0, 8, 8)
                .unwrap()
                .signal_mask(),
            LegacySignalMask::None
        );
    }
}
