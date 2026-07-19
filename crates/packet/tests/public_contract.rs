use thekernel_linux_packet::{
    AF_PACKET, BindPublication, DeliveryDecision, DeliveryDirection, FrameLayout, GetPacketOption,
    InterfaceIndex, LinkLayerAddress, LinkLayerInfo, MSG_PEEK, MSG_TRUNC, PacketBindRequest,
    PacketError, PacketOption, PacketOptionOperation, PacketOptionValue, PacketSocketState,
    PacketSocketType, PacketStatistics, ProtocolSelector, QueueDisposition, ReceiveFlags,
    SetPacketOption,
};

#[test]
fn normalized_bind_receive_and_statistics_contract_is_public() {
    let creation_protocol = ProtocolSelector::from_network_order_i32(i32::from(0x0800_u16.to_be()));
    let mut socket = PacketSocketState::new(PacketSocketType::Raw, creation_protocol);

    let request = PacketBindRequest::try_from_network_order_fields(AF_PACKET, 0, 11).unwrap();
    let plan = socket.prepare_bind(request).unwrap();
    assert_eq!(plan.expected().protocol().host_order(), 0x0800);
    assert_eq!(plan.replacement().protocol().host_order(), 0x0800);
    assert_eq!(socket.publish_bind(plan), Ok(BindPublication::Rebound));

    let mac = LinkLayerAddress::new([2, 0, 0, 0, 0, 1, 99, 99], 6).unwrap();
    let link = LinkLayerInfo::new(InterfaceIndex::exact(11).unwrap(), 1, mac).unwrap();
    let name = socket.get_name(Some(link)).unwrap();
    assert_eq!(name.interface().raw(), 11);
    assert_eq!(name.protocol().host_order(), 0x0800);
    assert_eq!(name.protocol_network_order(), 0x0800_u16.to_be());
    assert_eq!(name.address().as_bytes(), &[2, 0, 0, 0, 0, 1]);

    let flags = ReceiveFlags::from_bits(MSG_PEEK | MSG_TRUNC).unwrap();
    let view = FrameLayout::new(128, 14)
        .unwrap()
        .captured_view(PacketSocketType::Raw, 96)
        .unwrap();
    let receive = view.receive_decision(32, flags);
    assert_eq!(receive.copy_len(), 32);
    assert_eq!(receive.returned_len(), 96);
    assert!(receive.message_truncated());
    assert_eq!(receive.queue_disposition(), QueueDisposition::Retain);

    assert_eq!(
        socket.delivery_decision(
            DeliveryDirection::Incoming,
            0x0800,
            InterfaceIndex::exact(11).unwrap(),
        ),
        DeliveryDecision::Deliver
    );
    assert_eq!(
        socket.delivery_decision(
            DeliveryDirection::Outgoing,
            0x0800,
            InterfaceIndex::exact(11).unwrap(),
        ),
        DeliveryDecision::OutgoingRequiresAllProtocols
    );

    socket.set_option(SetPacketOption::decode(PacketOption::IgnoreOutgoing.raw(), 1).unwrap());
    assert!(socket.ignore_outgoing());

    assert_eq!(
        GetPacketOption::decode(PacketOption::Statistics.raw()),
        Ok(GetPacketOption::Statistics)
    );
    let endpoint_snapshot = PacketStatistics::from_destructive_snapshot(1, 1, 1, 1, false);
    let stats = match PacketOptionValue::Statistics(endpoint_snapshot) {
        PacketOptionValue::Statistics(stats) => stats,
        PacketOptionValue::IgnoreOutgoing(_) => panic!("statistics value changed variant"),
    };
    assert_eq!(stats.packets(), 3);
    assert_eq!(stats.drops(), 2);
    assert_eq!(stats.accepted(), 1);
    assert_eq!(stats.queue_drops(), 1);
    assert_eq!(stats.allocation_drops(), 1);
    assert_eq!(stats.filter_rejects(), 1);
    assert!(!stats.saturated());
}

#[test]
fn unsupported_surface_is_never_silently_accepted() {
    assert_eq!(
        GetPacketOption::decode(PacketOption::ReceiveRing.raw()),
        Err(PacketError::UnsupportedPacketOption {
            option: PacketOption::ReceiveRing,
            operation: PacketOptionOperation::Get,
        })
    );
    assert_eq!(
        PacketOption::from_raw(10_000),
        Err(PacketError::UnknownPacketOption)
    );
    assert_eq!(
        PacketSocketType::from_raw(1),
        Err(PacketError::UnsupportedSocketType)
    );
}
