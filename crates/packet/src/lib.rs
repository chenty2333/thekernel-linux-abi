//! Pure Linux AF_PACKET policy values and first-stage socket state.
//!
//! This crate owns normalized protocol and address values, bind publication,
//! ordinary receive-view decisions, supported packet options, and typed
//! conversion of endpoint-owned destructive statistics snapshots. It
//! deliberately does not own packet buffers, live counters, device taps,
//! queues, waiters, file descriptors, userspace memory, capabilities, network
//! namespaces, or syscall error conversion.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod address;
mod error;
mod options;
mod protocol;
mod receive;
mod socket;
mod statistics;

pub use address::{
    AF_PACKET, InterfaceIndex, LinkLayerAddress, LinkLayerInfo, MAX_LINK_LAYER_ADDRESS_LEN,
    PacketBindRequest, PacketSendAddress, PacketType, SockAddrLl,
};
pub use error::PacketError;
pub use options::{
    GetPacketOption, PacketOption, PacketOptionOperation, PacketOptionValue, SetPacketOption,
};
pub use protocol::{ETH_P_ALL, EtherType, ProtocolSelector};
pub use receive::{
    FrameLayout, MSG_PEEK, MSG_TRUNC, PacketView, QueueDisposition, ReceiveDecision, ReceiveFlags,
};
pub use socket::{
    BindPlan, BindPublication, BindingGeneration, DeliveryDecision, DeliveryDirection,
    PacketBinding, PacketSocketState, PacketSocketType,
};
pub use statistics::PacketStatistics;
