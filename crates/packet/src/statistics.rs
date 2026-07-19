/// Typed result of one endpoint-owned destructive statistics snapshot.
///
/// The Layer 1 packet endpoint remains the sole owner of live counters and
/// resets them exactly once. This value only maps that already-destructive
/// snapshot into Linux packet/drop totals plus reasoned diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketStatistics {
    packets: u64,
    drops: u64,
    accepted: u64,
    queue_drops: u64,
    allocation_drops: u64,
    filter_rejects: u64,
    saturated: bool,
}

impl PacketStatistics {
    /// Maps one endpoint-owned destructive snapshot without taking ownership
    /// of the counters or introducing a second reset point.
    ///
    /// Accepted packets and both post-filter drop categories contribute to the
    /// Linux packet total. Queue and allocation failures contribute to drops.
    /// Filter rejects contribute to neither. Aggregates saturate instead of
    /// failing a receive path; `source_saturated` propagates a lower counter's
    /// diagnostic marker.
    pub const fn from_destructive_snapshot(
        accepted: u64,
        queue_drops: u64,
        allocation_drops: u64,
        filter_rejects: u64,
        source_saturated: bool,
    ) -> Self {
        let (drops, drop_saturated) = saturating_sum(queue_drops, allocation_drops);
        let (packets, packet_saturated) = saturating_sum(accepted, drops);
        Self {
            packets,
            drops,
            accepted,
            queue_drops,
            allocation_drops,
            filter_rejects,
            saturated: source_saturated || drop_saturated || packet_saturated,
        }
    }

    /// Packets seen by the socket after filtering, including accounted drops.
    pub const fn packets(self) -> u64 {
        self.packets
    }

    /// Queue-full plus allocation-failure drops.
    pub const fn drops(self) -> u64 {
        self.drops
    }

    /// Packets successfully admitted to the ordinary queue.
    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    /// Packets dropped because the bounded queue was full.
    pub const fn queue_drops(self) -> u64 {
        self.queue_drops
    }

    /// Packets dropped because packet storage allocation failed.
    pub const fn allocation_drops(self) -> u64 {
        self.allocation_drops
    }

    /// Packets rejected by an attached filter before admission.
    ///
    /// This diagnostic counter is intentionally excluded from Linux-visible
    /// `packets` and `drops`.
    pub const fn filter_rejects(self) -> u64 {
        self.filter_rejects
    }

    /// Whether the endpoint or aggregate conversion saturated a counter.
    pub const fn saturated(self) -> bool {
        self.saturated
    }

    /// Returns whether every counter and diagnostic marker is zero.
    pub const fn is_empty(self) -> bool {
        self.packets == 0
            && self.drops == 0
            && self.accepted == 0
            && self.queue_drops == 0
            && self.allocation_drops == 0
            && self.filter_rejects == 0
            && !self.saturated
    }
}

const fn saturating_sum(left: u64, right: u64) -> (u64, bool) {
    match left.checked_add(right) {
        Some(sum) => (sum, false),
        None => (u64::MAX, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_excludes_filter_rejects_from_linux_totals() {
        let stats = PacketStatistics::from_destructive_snapshot(1, 2, 3, 5, false);
        assert_eq!(stats.packets(), 6);
        assert_eq!(stats.drops(), 5);
        assert_eq!(stats.accepted(), 1);
        assert_eq!(stats.queue_drops(), 2);
        assert_eq!(stats.allocation_drops(), 3);
        assert_eq!(stats.filter_rejects(), 5);
        assert!(!stats.saturated());
    }

    #[test]
    fn aggregation_saturates_without_creating_a_receive_error() {
        let stats = PacketStatistics::from_destructive_snapshot(u64::MAX, u64::MAX, 1, 0, false);
        assert_eq!(stats.packets(), u64::MAX);
        assert_eq!(stats.drops(), u64::MAX);
        assert!(stats.saturated());

        let lower = PacketStatistics::from_destructive_snapshot(0, 0, 0, 0, true);
        assert!(lower.saturated());
        assert!(!lower.is_empty());
    }
}
