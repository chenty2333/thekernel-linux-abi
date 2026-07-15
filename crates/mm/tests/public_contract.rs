use thekernel_linux_mm::*;

const PAGE: usize = 4096;

fn access(read: bool, write: bool, execute: bool) -> MappingAccess {
    MappingAccess::new(read, write, execute)
}

fn snapshot(
    mapping: u64,
    generation: u64,
    start: usize,
    length: usize,
    permissions: MappingAccess,
) -> MappingSnapshot {
    MappingSnapshot::from_raw(
        1,
        mapping,
        generation,
        start,
        length,
        PAGE,
        permissions.bits(),
        MappingKind::AnonymousPrivate,
        true,
        false,
    )
    .unwrap()
}

fn request(
    start: usize,
    length: usize,
    access: PinAccess,
    duration: PinDuration,
    owner: u64,
) -> PinRequest {
    PinRequest::from_raw(start, length, access, duration, PinUse::BlockIo, owner).unwrap()
}

fn registry<const O: usize, const T: usize>(
    quota: PinQuota,
    first_token: u64,
) -> PinRegistry<O, T> {
    let mut registry = PinRegistry::new(PAGE, quota, first_token).unwrap();
    registry
        .configure_owner(PinOwner::new(7).unwrap(), quota)
        .unwrap();
    registry
}

fn validate_single<const O: usize, const T: usize>(
    registry: &mut PinRegistry<O, T>,
    reservation: PinReservation,
    mapping: MappingSnapshot,
    covered: PageRange,
) {
    registry
        .revalidate_next(reservation, mapping.expected(), mapping, covered)
        .unwrap();
}

#[test]
fn public_values_keep_invariants_private_and_checked() {
    assert_eq!(AddressSpaceId::new(0), Err(MmError::InvalidIdentity));
    assert_eq!(MappingId::new(0), Err(MmError::InvalidIdentity));
    assert_eq!(PinOwner::new(0), Err(MmError::InvalidIdentity));
    assert_eq!(FaultHandlerId::new(0), Err(MmError::InvalidIdentity));
    assert_eq!(UserRange::new(usize::MAX - 1, 4), Err(MmError::Overflow));
    assert_eq!(PageRange::new(0x1001, PAGE, PAGE), Err(MmError::Unaligned));
    assert_eq!(MappingAccess::from_bits(0x80), Err(MmError::InvalidAccess));
    assert_eq!(
        FaultCapacity::new(1, u32::MAX, 1),
        Err(MmError::UnboundedLimit)
    );
}

#[test]
fn one_pin_can_revalidate_multiple_contiguous_mappings() {
    let quota = PinQuota::new(16, (16 * PAGE) as u64, 8);
    let mut registry = registry::<2, 8>(quota, 1);
    let address_space = AddressSpaceId::new(1).unwrap();
    let first = snapshot(10, 1, 0x1000, 0x2000, access(true, true, false));
    let second = snapshot(11, 4, 0x3000, 0x2000, access(true, true, false));
    let reservation = registry
        .reserve(
            request(0x1800, 0x2800, PinAccess::Read, PinDuration::AsyncIo, 7),
            address_space,
        )
        .unwrap();

    registry
        .revalidate_next(
            reservation,
            first.expected(),
            first,
            PageRange::new(0x1000, 0x2000, PAGE).unwrap(),
        )
        .unwrap();
    registry
        .revalidate_next(
            reservation,
            second.expected(),
            second,
            PageRange::new(0x3000, PAGE, PAGE).unwrap(),
        )
        .unwrap();
    let token = registry.commit(reservation).unwrap();
    let view = registry.view(token).unwrap();
    assert_eq!(view.token(), token);
    assert_eq!(view.request().access(), PinAccess::Read);
    assert_eq!(view.range(), PageRange::new(0x1000, 0x3000, PAGE).unwrap());
    assert_eq!(view.snapshot().address_space(), address_space);
    assert_eq!(view.snapshot().range(), view.range());
    assert_eq!(view.validated_mappings(), 2);
    assert!(view.is_active());
    assert_eq!(registry.active_count(), 1);
    assert_eq!(registry.global_accounting().pages(), 3);
    assert_eq!(registry.global_accounting().bytes(), (3 * PAGE) as u64);
}

#[test]
fn read_pins_may_overlap_but_any_write_overlap_is_rejected() {
    let quota = PinQuota::new(16, (16 * PAGE) as u64, 8);
    let mut registry = registry::<2, 8>(quota, 1);
    let asid = AddressSpaceId::new(1).unwrap();
    let mapping = snapshot(10, 1, 0x1000, 0x4000, access(true, true, false));
    let covered = PageRange::new(0x1000, 0x2000, PAGE).unwrap();

    let first = registry
        .reserve(
            request(0x1000, 0x2000, PinAccess::Read, PinDuration::Synchronous, 7),
            asid,
        )
        .unwrap();
    validate_single(&mut registry, first, mapping, covered);
    let first = registry.commit(first).unwrap();

    let second = registry
        .reserve(
            request(0x1800, PAGE, PinAccess::Read, PinDuration::AsyncIo, 7),
            asid,
        )
        .unwrap();
    validate_single(&mut registry, second, mapping, covered);
    let second = registry.commit(second).unwrap();

    assert_eq!(
        registry.reserve(
            request(0x2000, PAGE, PinAccess::Write, PinDuration::AsyncIo, 7),
            asid,
        ),
        Err(MmError::PinOverlap)
    );
    registry.release(first).unwrap();
    registry.release(second).unwrap();
}

#[test]
fn quota_failure_is_mutation_free_and_page_covering_is_accounted() {
    let quota = PinQuota::new(1, PAGE as u64, 1);
    let mut registry = registry::<1, 2>(quota, 1);
    assert_eq!(
        registry.reserve(
            request(0x1fff, 2, PinAccess::Read, PinDuration::Synchronous, 7),
            AddressSpaceId::new(1).unwrap(),
        ),
        Err(MmError::QuotaExceeded)
    );
    assert_eq!(registry.global_accounting(), PinAccounting::default());
    assert_eq!(registry.progress().total(), 0);
}

#[test]
fn stale_revalidation_rolls_back_reservation_and_both_quotas() {
    let quota = PinQuota::new(4, (4 * PAGE) as u64, 2);
    let mut registry = registry::<1, 2>(quota, 10);
    let old = snapshot(10, 1, 0x1000, PAGE, access(true, true, false));
    let replacement = snapshot(10, 2, 0x1000, PAGE, access(true, true, false));
    let reservation = registry
        .reserve(
            request(0x1000, PAGE, PinAccess::Write, PinDuration::AsyncIo, 7),
            AddressSpaceId::new(1).unwrap(),
        )
        .unwrap();
    assert_eq!(registry.global_accounting().tokens(), 1);
    assert_eq!(
        registry.revalidate_next(reservation, old.expected(), replacement, old.range()),
        Err(MmError::StaleGeneration)
    );
    assert_eq!(registry.global_accounting(), PinAccounting::default());
    assert_eq!(
        registry
            .owner_accounting(PinOwner::new(7).unwrap())
            .unwrap(),
        PinAccounting::default()
    );
    assert_eq!(
        registry.view(reservation.token()),
        Err(MmError::UnknownToken)
    );
}

#[test]
fn mapping_mutation_is_blocked_only_for_overlapping_live_pin_range() {
    let quota = PinQuota::new(8, (8 * PAGE) as u64, 4);
    let mut registry = registry::<1, 4>(quota, 1);
    let mapping = snapshot(10, 1, 0x1000, 0x4000, access(true, true, false));
    let reservation = registry
        .reserve(
            request(0x1000, PAGE, PinAccess::Read, PinDuration::AsyncIo, 7),
            mapping.address_space(),
        )
        .unwrap();
    validate_single(
        &mut registry,
        reservation,
        mapping,
        PageRange::new(0x1000, PAGE, PAGE).unwrap(),
    );
    let token = registry.commit(reservation).unwrap();

    let overlap =
        InvalidationRange::from_raw(mapping, 0x1000, PAGE, InvalidationReason::Unmap).unwrap();
    let disjoint =
        InvalidationRange::from_raw(mapping, 0x3000, PAGE, InvalidationReason::Protect).unwrap();
    assert_eq!(
        registry.admit_mutation(overlap),
        Err(MmError::MappingPinned)
    );
    let blocker = registry.first_mutation_blocker(overlap).unwrap();
    assert_eq!(blocker.token(), token);
    assert_eq!(blocker.request().owner(), PinOwner::new(7).unwrap());
    assert!(registry.admit_mutation(disjoint).is_ok());
    registry.release(token).unwrap();
    assert!(registry.admit_mutation(overlap).is_ok());
}

#[test]
fn close_and_forced_teardown_have_explicit_drain_states() {
    let quota = PinQuota::new(8, (8 * PAGE) as u64, 4);
    let mut closing = registry::<1, 4>(quota, 1);
    let mapping = snapshot(10, 1, 0x1000, PAGE, access(true, true, false));
    let reservation = closing
        .reserve(
            request(0x1000, PAGE, PinAccess::Read, PinDuration::AsyncIo, 7),
            mapping.address_space(),
        )
        .unwrap();
    validate_single(&mut closing, reservation, mapping, mapping.range());
    let token = closing.commit(reservation).unwrap();
    assert_eq!(closing.begin_close().unwrap().active(), 1);
    assert_eq!(
        closing.reserve(
            request(0x2000, PAGE, PinAccess::Read, PinDuration::AsyncIo, 7),
            mapping.address_space(),
        ),
        Err(MmError::Closing)
    );
    assert_eq!(closing.finish_teardown(), Err(MmError::Busy));
    closing.release(token).unwrap();
    closing.finish_teardown().unwrap();
    assert_eq!(closing.state(), PinRegistryState::Closed);

    let mut teardown = registry::<1, 4>(quota, 20);
    let pending = teardown
        .reserve(
            request(0x1000, PAGE, PinAccess::Read, PinDuration::AsyncIo, 7),
            mapping.address_space(),
        )
        .unwrap();
    assert!(!teardown.view(pending.token()).unwrap().is_active());
    let report = teardown.begin_teardown().unwrap();
    assert_eq!(report.cancelled_reservations(), 1);
    assert_eq!(report.active_remaining(), 0);
    assert_eq!(teardown.global_accounting(), PinAccounting::default());
    teardown.finish_teardown().unwrap();
}

#[test]
fn pin_token_sequence_exhausts_instead_of_wrapping() {
    let quota = PinQuota::new(2, (2 * PAGE) as u64, 1);
    let mut registry = registry::<1, 1>(quota, u64::MAX);
    let mapping = snapshot(10, 1, 0x1000, PAGE, access(true, false, false));
    let reservation = registry
        .reserve(
            request(0x1000, PAGE, PinAccess::Read, PinDuration::Synchronous, 7),
            mapping.address_space(),
        )
        .unwrap();
    validate_single(&mut registry, reservation, mapping, mapping.range());
    let token = registry.commit(reservation).unwrap();
    assert_eq!(token.get(), u64::MAX);
    registry.release(token).unwrap();
    assert_eq!(
        registry.reserve(
            request(0x1000, PAGE, PinAccess::Read, PinDuration::Synchronous, 7),
            mapping.address_space(),
        ),
        Err(MmError::IdExhausted)
    );
    assert_eq!(registry.global_accounting(), PinAccounting::default());
}

#[test]
fn fault_admission_is_bounded_and_completion_rejects_stale_generation() {
    let mapping = snapshot(20, 7, 0x8000, 0x2000, access(true, true, false));
    let key = FaultKey::from_address(mapping, 0x9000, FaultAccess::Write).unwrap();
    let request = FaultRequest::new(
        key,
        FaultHandlerId::new(5).unwrap(),
        FaultType::WriteProtect,
    );
    let capacity = FaultCapacity::new(2, 2, 4).unwrap();
    let permit = FaultAdmission::check(
        request,
        mapping,
        capacity,
        FaultLoad::new(1, 1, 3),
        FaultLifecycleState::Open,
    )
    .unwrap();
    assert_eq!(permit.request(), request);
    assert_eq!(
        FaultAdmission::check(
            request,
            mapping,
            capacity,
            FaultLoad::new(2, 1, 3),
            FaultLifecycleState::Open,
        ),
        Err(MmError::QuotaExceeded)
    );

    let completion = validate_fault_completion(
        mapping_request(request),
        mapping,
        FaultDisposition::Continue,
    )
    .unwrap();
    assert_eq!(completion.disposition(), FaultDisposition::Continue);
    let replacement = snapshot(20, 8, 0x8000, 0x2000, access(true, true, false));
    assert_eq!(
        validate_fault_completion(request, replacement, FaultDisposition::Supply),
        Err(MmError::StaleGeneration)
    );
}

fn mapping_request(request: FaultRequest) -> FaultRequest {
    request
}

#[test]
fn remap_fragments_share_one_anchor_and_low_address_affine_rebases() {
    let old = PageRange::new(0x8000, 0x4000, PAGE).unwrap();
    let remap = RemapGeometry::new(old, 0x1000, 0x6000).unwrap();
    let first = remap
        .segment(PageRange::new(0x8000, PAGE, PAGE).unwrap())
        .unwrap();
    let second = remap
        .segment(PageRange::new(0xa000, 0x2000, PAGE).unwrap())
        .unwrap();
    assert_eq!(first.destination().start(), 0x1000);
    assert_eq!(second.destination().start(), 0x3000);
    assert_eq!(first.backend_old_start(), old.start());
    assert_eq!(second.backend_old_start(), old.start());
    assert_eq!(first.backend_new_start(), 0x1000);
    assert_eq!(second.backend_new_start(), 0x1000);
    assert_eq!(remap.growth_tail().unwrap().unwrap().start(), 0x5000);

    let relocation = relocate_affine_origin(0x4000, 0x8000, 0x1000).unwrap();
    assert_eq!(relocation.origin(), 0x1000);
    assert_eq!(relocation.backing_advance(), 0x4000);
    assert_eq!(
        remap.segment(PageRange::new(0xc000, PAGE, PAGE).unwrap()),
        Err(MmError::InvalidRemap)
    );
}
