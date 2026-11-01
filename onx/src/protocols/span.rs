//! Position of a header in the raw bytes of its packet

use std::ops::Range;

use crate::core::packet::RawPacket;

/// Position of a header in its raw packet: byte offset and length.
///
/// Decoded headers own copies of their fields and do not borrow the packet
/// data. A `Span` is the way back to the original bytes, when they are
/// available (payload inspection, hex dumps, fields not extracted).
///
/// Offsets are `u32`, not `u16`: captures can hold coalesced segments
/// (GRO/TSO, BIG TCP) larger than 64 KiB.
///
/// Not `std::ops::Range<u32>`: `Range` is an iterator, so it is deliberately
/// not `Copy`, which would prevent headers holding a span from being `Copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    offset: u32,
    len: u32,
}

impl Span {
    /// Create a span of `len` bytes starting at `offset`
    pub const fn new(offset: u32, len: u32) -> Self {
        Self { offset, len }
    }

    /// Returns the offset of the first byte, from the start of the packet
    pub const fn offset(self) -> u32 {
        self.offset
    }

    /// Returns the number of bytes covered
    pub const fn len(self) -> u32 {
        self.len
    }

    /// Returns true if the span covers no bytes
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Returns the covered positions as a range, usable to index a slice
    pub fn range(self) -> Range<usize> {
        // u32 -> usize is lossless on the 32 and 64-bit targets onx supports
        let start = self.offset as usize;
        start..start + self.len as usize
    }

    /// Returns the bytes covered by this span in `packet`, or `None` if the
    /// span goes past the captured data (e.g. a packet truncated by snaplen).
    ///
    /// The span must come from a header decoded from this same packet.
    pub fn bytes(self, packet: &RawPacket) -> Option<&[u8]> {
        packet.data().get(self.range())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::{LinkType, PacketId};
    use time::OffsetDateTime;

    fn packet(data: Vec<u8>) -> RawPacket {
        let len = data.len();
        RawPacket::new(
            PacketId::FIRST,
            OffsetDateTime::UNIX_EPOCH,
            data,
            len,
            LinkType::Ethernet,
        )
    }

    #[test]
    fn range_matches_offset_and_len() {
        assert_eq!(Span::new(14, 20).range(), 14..34);
    }

    #[test]
    fn bytes_inside_packet() {
        let packet = packet(vec![0, 1, 2, 3, 4, 5]);
        assert_eq!(Span::new(2, 3).bytes(&packet), Some(&[2, 3, 4][..]));
    }

    #[test]
    fn bytes_up_to_the_last_byte() {
        let packet = packet(vec![0, 1, 2, 3]);
        assert_eq!(Span::new(1, 3).bytes(&packet), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn bytes_past_the_captured_data() {
        // Header announced longer than what the capture kept
        let packet = packet(vec![0, 1, 2, 3]);
        assert_eq!(Span::new(2, 10).bytes(&packet), None);
        assert_eq!(Span::new(10, 1).bytes(&packet), None);
    }
}
