//! Defines the `PacketSource` trait and related types for reading packets from different capture formats (PCAP, PCAPNG, etc).
//! This module provides a unified interface for iterating over packets from various sources, allowing the rest of the codebase to work with a common `NxPacket` type regardless of the underlying capture format.

use crate::core::packet::NxPacket;
use std::error;

/// Generic packet source trait that can be implemented by different capture formats (PCAP, PCAPNG, live capture, etc).
/// It exposes a common interface to iterate over packets, while allowing different underlying implementations.
pub trait PacketSource {
    type Error: error::Error + Send + Sync + 'static;
    type PacketIter: Iterator<Item = Result<NxPacket, Self::Error>>;
    fn packets(self) -> Self::PacketIter;
}
