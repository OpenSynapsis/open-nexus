//! Why decoding of a packet ended early

use std::fmt;

use crate::core::packet::LinkType;
use crate::protocols::header::HeaderKind;
use crate::protocols::numbers::{EtherType, IpProtocol};

/// Why decoding of a packet ended before its normal end.
///
/// Decoding keeps the headers decoded before the stop: this is an outcome of
/// a partial decoding, not an error. A packet whose decoding reaches its
/// normal end (e.g. the payload after TCP or UDP) has no `Stop`.
///
/// `Copy`, `Eq` and `Hash`, so that stops can be counted by reason
/// (`HashMap<Stop, usize>`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stop {
    /// The captured data ends inside this header (e.g. snaplen)
    Truncated(HeaderKind),
    /// This header is present but invalid
    Malformed(HeaderKind),
    /// The link layer of the packet is not decoded by onx
    UnsupportedLinkType(LinkType),
    /// The protocol carried by an Ethernet frame is not decoded by onx
    UnsupportedEtherType(EtherType),
    /// The protocol carried by an IP packet is not decoded by onx
    UnsupportedIpProtocol(IpProtocol),
    /// The packet has more nested headers than onx decodes
    TooDeep,
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stop::Truncated(header) => write!(f, "truncated {} header", header),
            Stop::Malformed(header) => write!(f, "malformed {} header", header),
            Stop::UnsupportedLinkType(link_type) => {
                write!(f, "unsupported link type: {}", link_type)
            }
            Stop::UnsupportedEtherType(ether_type) => {
                write!(f, "unsupported EtherType: {}", ether_type)
            }
            Stop::UnsupportedIpProtocol(proto) => write!(f, "unsupported IP protocol: {}", proto),
            Stop::TooDeep => write!(f, "too many nested headers"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_truncated_and_malformed() {
        assert_eq!(
            Stop::Truncated(HeaderKind::Tcp).to_string(),
            "truncated TCP header"
        );
        assert_eq!(
            Stop::Malformed(HeaderKind::Ipv4).to_string(),
            "malformed IPv4 header"
        );
    }

    #[test]
    fn display_unsupported() {
        assert_eq!(
            Stop::UnsupportedLinkType(LinkType::Other(147)).to_string(),
            "unsupported link type: Unknown (147)"
        );
        assert_eq!(
            Stop::UnsupportedEtherType(EtherType::from(0x0806)).to_string(),
            "unsupported EtherType: 0x0806"
        );
        assert_eq!(
            Stop::UnsupportedIpProtocol(IpProtocol::from(47)).to_string(),
            "unsupported IP protocol: 47"
        );
    }

    #[test]
    fn display_too_deep() {
        assert_eq!(Stop::TooDeep.to_string(), "too many nested headers");
    }

    #[test]
    fn stops_can_be_counted_by_reason() {
        use std::collections::HashMap;

        let mut counts: HashMap<Stop, usize> = HashMap::new();
        for stop in [
            Stop::Truncated(HeaderKind::Tcp),
            Stop::UnsupportedEtherType(EtherType::from(0x0806)),
            Stop::Truncated(HeaderKind::Tcp),
        ] {
            *counts.entry(stop).or_default() += 1;
        }

        assert_eq!(counts[&Stop::Truncated(HeaderKind::Tcp)], 2);
        assert_eq!(counts.len(), 2);
    }
}
