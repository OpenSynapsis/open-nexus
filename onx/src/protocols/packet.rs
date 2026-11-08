//! Decoded packet: metadata and the stack of decoded headers

use arrayvec::ArrayVec;
use time::OffsetDateTime;

use crate::core::packet::PacketId;
use crate::protocols::{Header, Stop};

/// Maximum number of headers decoded in one packet.
///
/// A bound against crafted packets nesting headers without end: decoding
/// stops with [`Stop::TooDeep`] instead of doing unbounded work. A real
/// VXLAN stack (Ethernet, 2 VLAN tags, IPv4, UDP, VXLAN, Ethernet, IPv4, TCP)
/// already has 9 headers.
pub const MAX_DEPTH: usize = 16;

/// A decoded packet: its metadata and its headers, outermost first.
///
/// Built by [`RawPacket::decode`](crate::core::packet::RawPacket::decode).
/// Owns its data (no reference to the raw bytes), so it can outlive them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    id: PacketId,
    timestamp: OffsetDateTime,
    original_len: usize,
    headers: ArrayVec<Header, MAX_DEPTH>,
    stopped: Option<Stop>,
}

impl Packet {
    pub(crate) fn new(
        id: PacketId,
        timestamp: OffsetDateTime,
        original_len: usize,
        headers: ArrayVec<Header, MAX_DEPTH>,
        stopped: Option<Stop>,
    ) -> Self {
        Self {
            id,
            timestamp,
            original_len,
            headers,
            stopped,
        }
    }

    /// Returns the identity of this packet (its position in the capture)
    pub fn id(&self) -> PacketId {
        self.id
    }

    /// Returns the timestamp when this packet was captured
    pub fn timestamp(&self) -> OffsetDateTime {
        self.timestamp
    }

    /// Returns the length of the packet as it was on the wire
    pub fn original_len(&self) -> usize {
        self.original_len
    }

    /// Returns the decoded headers, outermost first
    pub fn headers(&self) -> &[Header] {
        &self.headers
    }

    /// Returns why decoding ended early, or `None` if it reached its normal end
    pub fn stopped(&self) -> Option<Stop> {
        self.stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_size_stays_reasonable() {
        // Headers are stored inline: this bound makes growth a conscious
        // decision (e.g. when adding IPv6 or raising MAX_DEPTH).
        let size = std::mem::size_of::<Packet>();
        assert!(size <= 1024, "Packet is {size} bytes");
    }
}
