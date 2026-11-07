//! Ethernet II

use std::fmt;

use crate::protocols::{EtherType, Span};

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

#[cfg(test)]
mod tests {
    use super::*;

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
