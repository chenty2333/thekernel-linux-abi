use crate::*;

const PAGE: usize = 4096;

#[test]
fn checked_ranges_reject_zero_overflow_and_unaligned_pages() {
    assert_eq!(UserRange::new(0x1000, 0), Err(MmError::ZeroLength));
    assert_eq!(UserRange::new(usize::MAX, 2), Err(MmError::Overflow));
    assert_eq!(
        UserRange::new_bounded(0x3000, 0x2000, 0x4000),
        Err(MmError::AddressOutOfRange)
    );
    assert_eq!(
        UserRange::new_bounded(0x3000, 0x1000, 0x4000)
            .unwrap()
            .end(),
        0x4000
    );
    assert_eq!(PageSize::new(3000), Err(MmError::InvalidPageSize));
    assert_eq!(PageRange::new(0x1001, PAGE, PAGE), Err(MmError::Unaligned));
    assert_eq!(
        PageRange::new(0x1000, PAGE - 1, PAGE),
        Err(MmError::Unaligned)
    );
}

#[test]
fn page_covering_reports_both_partial_edges() {
    let requested = UserRange::new(0x1801, 0x1000).unwrap();
    let plan = PageCoveringPlan::new(requested, PAGE).unwrap();
    assert_eq!(plan.pages(), PageRange::new(0x1000, 0x2000, PAGE).unwrap());
    assert_eq!(plan.leading_bytes(), 0x801);
    assert_eq!(plan.trailing_bytes(), 0x7ff);
}

#[test]
fn generations_and_affine_origins_never_wrap_or_underflow() {
    assert_eq!(MappingGeneration::new(0), Err(MmError::InvalidIdentity));
    assert_eq!(
        MappingGeneration::new(u64::MAX).unwrap().next(),
        Err(MmError::IdExhausted)
    );

    let rebased = relocate_affine_origin(0x4000, 0x8000, 0x1000).unwrap();
    assert_eq!(rebased.origin(), 0x1000);
    assert_eq!(rebased.backing_advance(), 0x4000);

    let affine = relocate_affine_origin(0x4000, 0x8000, 0x10_000).unwrap();
    assert_eq!(affine.origin(), 0xc000);
    assert_eq!(affine.backing_advance(), 0);
}

#[test]
fn memlock_planner_charges_only_new_bytes() {
    let plan = MemlockPlan::new(0x4000, 0x1000, 0x3000, MemlockLimit::Limited(0x6000)).unwrap();
    assert_eq!(plan.additional_bytes(), 0x2000);
    assert_eq!(plan.total_locked_bytes(), 0x6000);
    assert_eq!(
        MemlockPlan::new(0, 0, PAGE as u64, MemlockLimit::Disabled),
        Err(MmError::MemlockDenied)
    );
    assert_eq!(
        MemlockPlan::new(0, 2, 1, MemlockLimit::Unlimited),
        Err(MmError::InconsistentAccounting)
    );
}
