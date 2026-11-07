//! Ethernet II

use std::fmt;

use etherparse::Ethernet2HeaderSlice;

use crate::protocols::{next::Next, EtherType, HeaderKind, Span, Stop};

/// IEEE 802 MAC address
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Create a MAC address from its six bytes, in transmission order
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// Returns the six bytes of the address
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [first, rest @ ..] = self.0;
        write!(f, "{:02x}", first)?;
        for byte in rest {
            write!(f, ":{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// Ethernet II header
///
/// `#[non_exhaustive]`: other crates can read the fields, but cannot build
/// the struct with a literal or destructure it without `..`, so fields can
/// be added without a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ethernet {
    /// Destination MAC address
    pub destination: MacAddr,
    /// Source MAC address
    pub source: MacAddr,
    /// Protocol carried by the frame
    pub ether_type: EtherType,
    /// Position of the header in the raw packet
    pub span: Span,
}

impl Ethernet {
    /// Length of an Ethernet II header, in bytes
    const LEN: u32 = 14;

    /// Decode an Ethernet II header.
    ///
    /// `bytes` starts at the header; `offset` is its position in the raw
    /// packet, recorded in the header's span.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "called by the dissection loop (step 5)")
    )]
    pub(crate) fn decode(bytes: &[u8], offset: u32) -> Result<(Ethernet, Next), Stop> {
        let header_slice = Ethernet2HeaderSlice::from_slice(bytes)
            .map_err(|_| Stop::Truncated(HeaderKind::Ethernet))?;

        let ether_type = EtherType::from(header_slice.ether_type().0);

        let ether = Ethernet {
            destination: MacAddr(header_slice.destination()),
            source: MacAddr(header_slice.source()),
            ether_type,
            span: Span::new(offset, Self::LEN),
        };

        Ok((ether, Next::EtherType(ether_type)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet header (broadcast destination, IPv4) followed by `payload`
    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xff; 6];
        bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]);
        bytes.extend_from_slice(&[0x08, 0x00]);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn decode_fields() {
        let (ethernet, next) = Ethernet::decode(&frame(&[0xaa; 20]), 0).unwrap();

        assert_eq!(ethernet.destination, MacAddr::new([0xff; 6]));
        assert_eq!(ethernet.source, MacAddr::new([0x02, 0, 0, 0, 0, 0x01]));
        assert_eq!(ethernet.ether_type, EtherType::IPV4);
        assert_eq!(ethernet.span, Span::new(0, 14));
        assert_eq!(next, Next::EtherType(EtherType::IPV4));
    }

    #[test]
    fn decode_records_offset_in_span() {
        // e.g. an inner Ethernet frame inside a tunnel
        let (ethernet, _) = Ethernet::decode(&frame(&[]), 50).unwrap();
        assert_eq!(ethernet.span, Span::new(50, 14));
    }

    #[test]
    fn decode_truncated() {
        let bytes = frame(&[]);
        assert_eq!(
            Ethernet::decode(&bytes[..10], 0),
            Err(Stop::Truncated(HeaderKind::Ethernet))
        );
    }

    #[test]
    fn mac_display() {
        let mac = MacAddr::new([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(mac.to_string(), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn mac_display_broadcast() {
        let mac = MacAddr::new([0xff; 6]);
        assert_eq!(mac.to_string(), "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn mac_debug() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(format!("{mac:?}"), "MacAddr(02:00:00:00:00:01)");
    }
}
